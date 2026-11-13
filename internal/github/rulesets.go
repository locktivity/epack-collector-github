package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
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
	// RequiredChecks counts the checks a required_status_checks rule names.
	// GitHub's rule takes no effect until it names one.
	RequiredChecks int
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
		page, link, err := c.getRulesPage(ctx, next, path)
		if err != nil {
			return nil, err
		}
		rules = append(rules, page...)
		next = ""
		if m := linkNextRe.FindStringSubmatch(link); m != nil {
			next = m[1]
		}
	}
	return rules, nil
}

// getRulesPage reads one page of a branch's rules and the page's Link
// header. A rule it cannot read makes the page invalid.
func (c *Client) getRulesPage(ctx context.Context, pageURL, path string) ([]BranchRule, string, error) {
	resp, err := c.do(ctx, componentsdk.Operation{Name: "github.branch_rules.list"}, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var items []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, "", componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding rules: %w", path, err))
	}
	rules := make([]BranchRule, 0, len(items))
	for _, raw := range items {
		rule, err := parseBranchRule(raw)
		if err != nil {
			return nil, "", componentsdk.ResponseError(resp, fmt.Errorf("%s: %w", path, err))
		}
		rules = append(rules, rule)
	}
	return rules, resp.Header.Get("Link"), nil
}

// parseBranchRule reads one rule. GitHub's ruleset schemas require a rule's
// type, each pull_request parameter the collector reads, and a
// required_status_checks rule's list of checks. A rule without them would
// read as protection the branch does not have.
func parseBranchRule(raw json.RawMessage) (BranchRule, error) {
	var r struct {
		Type              *string         `json:"type"`
		RulesetSourceType string          `json:"ruleset_source_type"`
		RulesetSource     string          `json:"ruleset_source"`
		RulesetID         int64           `json:"ruleset_id"`
		Parameters        json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return BranchRule{}, fmt.Errorf("decoding rule: %w", err)
	}
	if r.Type == nil {
		return BranchRule{}, invalidResponse("a rule has no type")
	}
	rule := BranchRule{
		Type:              *r.Type,
		RulesetSourceType: r.RulesetSourceType,
		RulesetSource:     r.RulesetSource,
		RulesetID:         r.RulesetID,
	}
	switch rule.Type {
	case RuleTypePullRequest:
		var params struct {
			RequiredApprovingReviewCount *int  `json:"required_approving_review_count"`
			DismissStaleReviewsOnPush    *bool `json:"dismiss_stale_reviews_on_push"`
			RequireCodeOwnerReview       *bool `json:"require_code_owner_review"`
		}
		if len(r.Parameters) > 0 {
			if err := json.Unmarshal(r.Parameters, &params); err != nil {
				return BranchRule{}, fmt.Errorf("decoding pull_request rule parameters: %w", err)
			}
		}
		if params.RequiredApprovingReviewCount == nil || params.DismissStaleReviewsOnPush == nil || params.RequireCodeOwnerReview == nil {
			return BranchRule{}, invalidResponse("a pull_request rule has no required_approving_review_count, dismiss_stale_reviews_on_push, or require_code_owner_review")
		}
		rule.PullRequest = &PullRequestRuleParameters{
			RequiredApprovingReviewCount: *params.RequiredApprovingReviewCount,
			DismissStaleReviewsOnPush:    *params.DismissStaleReviewsOnPush,
			RequireCodeOwnerReview:       *params.RequireCodeOwnerReview,
		}
	case RuleTypeRequiredStatusChecks:
		var params struct {
			RequiredStatusChecks *[]json.RawMessage `json:"required_status_checks"`
		}
		if len(r.Parameters) > 0 {
			if err := json.Unmarshal(r.Parameters, &params); err != nil {
				return BranchRule{}, fmt.Errorf("decoding required_status_checks rule parameters: %w", err)
			}
		}
		if params.RequiredStatusChecks == nil {
			return BranchRule{}, invalidResponse("a required_status_checks rule has no required_status_checks")
		}
		rule.RequiredChecks = len(*params.RequiredStatusChecks)
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

// actorsWithIDs are the bypass actor types GitHub's ruleset schema requires
// an actor_id for. It ignores the ID of an OrganizationAdmin and sends null
// for a DeployKey.
var actorsWithIDs = []string{BypassActorIntegration, BypassActorRepositoryRole, BypassActorTeam, BypassActorUser}

// checkBypassActor returns an invalid_response error for a bypass actor with
// no actor_type, which GitHub's schema requires, or with no actor_id where
// the schema requires one. Without its type, an actor could be the
// organization admins, who would then read as held to the ruleset.
func checkBypassActor(actorType string, actorID *int64) error {
	switch {
	case actorType == "":
		return invalidResponse("lists a bypass actor with no actor_type")
	case actorID == nil && slices.Contains(actorsWithIDs, actorType):
		return invalidResponse("lists a %s bypass actor with no actor_id", actorType)
	}
	return nil
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
	resp, err := c.getJSONResponse(ctx, "github.rulesets.get", path, &body)
	if err != nil {
		return nil, err
	}
	if body.ID == 0 || body.Enforcement == "" {
		return nil, componentsdk.ResponseError(resp, invalidResponse("%s response has no id or enforcement", trimQuery(path)))
	}
	if body.BypassActors != nil {
		for _, a := range *body.BypassActors {
			if err := checkBypassActor(a.ActorType, a.ActorID); err != nil {
				return nil, componentsdk.ResponseError(resp, fmt.Errorf("%s response %w", trimQuery(path), err))
			}
		}
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
