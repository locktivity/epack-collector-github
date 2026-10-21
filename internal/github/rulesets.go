package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// Ruleset rule types the collector maps onto branch protection settings.
const (
	RuleTypePullRequest           = "pull_request"
	RuleTypeRequiredStatusChecks  = "required_status_checks"
	RuleTypeRequiredSignatures    = "required_signatures"
	RuleTypeNonFastForward        = "non_fast_forward"
	RuleTypeDeletion              = "deletion"
	RuleTypeRequiredLinearHistory = "required_linear_history"
)

// RulesetEnforcementActive is the only enforcement status under which GitHub
// applies a ruleset's rules. "evaluate" only reports what the rules would have
// blocked, and "disabled" does nothing.
const RulesetEnforcementActive = "active"

// Bypass actor types GitHub reports on a ruleset.
const (
	BypassActorOrganizationAdmin = "OrganizationAdmin"
	BypassActorRepositoryRole    = "RepositoryRole"
	BypassActorTeam              = "Team"
	BypassActorIntegration       = "Integration"
	BypassActorDeployKey         = "DeployKey"
	BypassActorUser              = "User"
)

// BranchRule is one rule that an active ruleset applies to a branch.
type BranchRule struct {
	Type              string
	RulesetSourceType string // Repository, Organization, or Enterprise
	RulesetSource     string // owner/repo for a repository ruleset, the owner login otherwise
	RulesetID         int64
	PullRequest       *PullRequestRuleParameters // set for pull_request rules only
}

// PullRequestRuleParameters are the pull_request rule settings the collector reads.
type PullRequestRuleParameters struct {
	RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
	DismissStaleReviewsOnPush    bool `json:"dismiss_stale_reviews_on_push"`
	RequireCodeOwnerReview       bool `json:"require_code_owner_review"`
}

// BranchRulesPageCap bounds pagination of one branch's rules (100 per page).
const BranchRulesPageCap = 10

// GetBranchRules returns the rules that active rulesets apply to a branch,
// whether the ruleset belongs to the repository, its organization, or its
// enterprise. GitHub leaves out rules from rulesets in evaluate or disabled
// enforcement. Requires metadata:read.
//
// Any failure, including one on a later page, returns an error and no rules,
// because a partial rule list would understate protection.
func (c *Client) GetBranchRules(ctx context.Context, owner, repo, branch string) ([]BranchRule, error) {
	path := fmt.Sprintf("/repos/%s/%s/rules/branches/%s?per_page=100", owner, repo, escapeRefPath(branch))
	next := c.baseURL + path
	var rules []BranchRule

	for page := 0; next != ""; page++ {
		if page == BranchRulesPageCap {
			return nil, fmt.Errorf("%s: more than %d pages of rules", path, BranchRulesPageCap)
		}
		items, link, err := c.getRulesPage(ctx, next, path)
		if err != nil {
			return nil, err
		}
		for _, raw := range items {
			rule, err := parseBranchRule(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			rules = append(rules, rule)
		}
		next = ""
		if m := linkNextRe.FindStringSubmatch(link); m != nil {
			next = m[1]
		}
	}
	return rules, nil
}

func (c *Client) getRulesPage(ctx context.Context, pageURL, path string) ([]json.RawMessage, string, error) {
	resp, err := c.do(ctx, componentsdk.Operation{Name: "github.branch_rules.list"}, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var items []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, "", componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding rules: %w", path, err))
	}
	return items, resp.Header.Get("Link"), nil
}

func parseBranchRule(raw json.RawMessage) (BranchRule, error) {
	var r struct {
		Type              string          `json:"type"`
		RulesetSourceType string          `json:"ruleset_source_type"`
		RulesetSource     string          `json:"ruleset_source"`
		RulesetID         int64           `json:"ruleset_id"`
		Parameters        json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return BranchRule{}, fmt.Errorf("decoding rule: %w", err)
	}
	rule := BranchRule{
		Type:              r.Type,
		RulesetSourceType: r.RulesetSourceType,
		RulesetSource:     r.RulesetSource,
		RulesetID:         r.RulesetID,
	}
	if r.Type == RuleTypePullRequest {
		var params PullRequestRuleParameters
		if err := json.Unmarshal(r.Parameters, &params); err != nil {
			return BranchRule{}, fmt.Errorf("decoding pull_request rule parameters: %w", err)
		}
		rule.PullRequest = &params
	}
	return rule, nil
}

// escapeRefPath escapes each segment of a branch name for a URL path and
// keeps the slashes, which are legal in branch names.
func escapeRefPath(ref string) string {
	segments := strings.Split(ref, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/")
}

// Ruleset is a ruleset's identity, enforcement, and bypass list.
type Ruleset struct {
	ID          int64
	Name        string
	SourceType  string
	Source      string
	Enforcement string
	// BypassVisible is false when GitHub left out bypass_actors, which it does
	// unless the caller has write access to the ruleset. When true, an empty
	// BypassActors means no one may bypass the ruleset.
	BypassVisible bool
	BypassActors  []BypassActor
}

// BypassActor is one actor allowed to bypass a ruleset. ActorID is nil when
// GitHub reports none, as it does for deploy keys.
type BypassActor struct {
	ActorType  string
	ActorID    *int64
	BypassMode string
}

// GetRepoRuleset fetches a ruleset through the repository endpoint with
// includes_parents=true, which also returns organization and enterprise
// rulesets that apply to the repository. The organization endpoint needs
// organization administration:write, while this one needs only metadata:read.
func (c *Client) GetRepoRuleset(ctx context.Context, owner, repo string, rulesetID int64) (*Ruleset, error) {
	var body struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		SourceType   string `json:"source_type"`
		Source       string `json:"source"`
		Enforcement  string `json:"enforcement"`
		BypassActors *[]struct {
			ActorID    *int64 `json:"actor_id"`
			ActorType  string `json:"actor_type"`
			BypassMode string `json:"bypass_mode"`
		} `json:"bypass_actors"`
	}
	path := fmt.Sprintf("/repos/%s/%s/rulesets/%d?includes_parents=true", owner, repo, rulesetID)
	if err := c.getJSON(ctx, "github.rulesets.get", path, &body); err != nil {
		return nil, err
	}
	if body.ID == 0 || body.Enforcement == "" {
		return nil, invalidResponse("%s response has no id or enforcement", trimQuery(path))
	}

	rs := &Ruleset{
		ID:          body.ID,
		Name:        body.Name,
		SourceType:  body.SourceType,
		Source:      body.Source,
		Enforcement: body.Enforcement,
	}
	if body.BypassActors != nil {
		rs.BypassVisible = true
		rs.BypassActors = make([]BypassActor, 0, len(*body.BypassActors))
		for _, a := range *body.BypassActors {
			rs.BypassActors = append(rs.BypassActors, BypassActor{
				ActorType:  a.ActorType,
				ActorID:    a.ActorID,
				BypassMode: a.BypassMode,
			})
		}
	}
	return rs, nil
}
