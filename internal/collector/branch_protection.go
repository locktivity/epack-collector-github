package collector

import (
	"slices"
	"strings"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// Effective protection rules, named as they appear in the output.
const (
	rulePullRequestRequired          = "pull_request_required"
	ruleApprovingReviews             = "approving_reviews"
	ruleRequiredApprovingReviewCount = "required_approving_review_count"
	ruleDismissStaleReviews          = "dismiss_stale_reviews"
	ruleCodeOwnerReviews             = "code_owner_reviews"
	ruleStatusChecks                 = "status_checks"
	ruleSignedCommits                = "signed_commits"
	ruleForcePushesBlocked           = "force_pushes_blocked"
	ruleDeletionsBlocked             = "deletions_blocked"
	ruleLinearHistory                = "linear_history"
)

// protectionRules are the on/off rules of effective protection.
var protectionRules = []string{
	rulePullRequestRequired,
	ruleApprovingReviews,
	ruleDismissStaleReviews,
	ruleCodeOwnerReviews,
	ruleStatusChecks,
	ruleSignedCommits,
	ruleForcePushesBlocked,
	ruleDeletionsBlocked,
	ruleLinearHistory,
}

// mechanismClassic names a classic branch protection rule as the source of a
// rule. Rulesets are named after their source type, such as
// organization_ruleset.
const mechanismClassic = "classic_branch_protection"

func rulesetMechanism(sourceType string) string {
	return strings.ToLower(sourceType) + "_ruleset"
}

// ruleSource is one mechanism supplying a rule. rulesetID is zero for classic
// branch protection.
type ruleSource struct {
	mechanism string
	rulesetID int64
}

// appliedRuleset is a ruleset with at least one rule on the default branch.
// detail is nil when the ruleset could not be read.
type appliedRuleset struct {
	id         int64
	sourceType string
	source     string
	ruleTypes  []string
	detail     *github.Ruleset
}

// repoProtection is a repository's effective default-branch protection: its
// classic branch protection rule combined with the rules of active rulesets.
// When rulesKnown is false the ruleset rules could not be read, so a rule that
// classic protection does not supply is unknown rather than absent.
type repoProtection struct {
	classic    *github.BranchProtectionRule
	rulesKnown bool
	supplied   map[string][]ruleSource
	approvals  int
	rulesets   []appliedRuleset
	admin      *bool
}

// evaluateProtection combines a repository's classic branch protection rule
// with the ruleset rules on its default branch. details maps ruleset IDs to
// their details, with nil for a ruleset that could not be read. Rules from a
// ruleset whose details show an enforcement other than active are left out.
func evaluateProtection(classic *github.BranchProtectionRule, rules []github.BranchRule, rulesKnown bool, details map[int64]*github.Ruleset) *repoProtection {
	p := &repoProtection{classic: classic, rulesKnown: rulesKnown, supplied: map[string][]ruleSource{}}
	if classic != nil {
		p.supplyClassic(classic)
	}
	for _, rule := range rules {
		detail := details[rule.RulesetID]
		p.recordRuleset(rule, detail)
		if detail != nil && detail.Enforcement != github.RulesetEnforcementActive {
			continue
		}
		p.supplyRule(rule)
	}
	p.admin = p.adminEnforcement()
	return p
}

func (p *repoProtection) supplyClassic(bp *github.BranchProtectionRule) {
	src := ruleSource{mechanism: mechanismClassic}
	if bp.RequiresApprovingReviews {
		p.supply(rulePullRequestRequired, src)
		p.supplyApprovals(bp.RequiredApprovingReviewCount, src)
	}
	if bp.DismissesStaleReviews {
		p.supply(ruleDismissStaleReviews, src)
	}
	if bp.RequiresCodeOwnerReviews {
		p.supply(ruleCodeOwnerReviews, src)
	}
	if bp.RequiresStatusChecks {
		p.supply(ruleStatusChecks, src)
	}
	if bp.RequiresCommitSignatures {
		p.supply(ruleSignedCommits, src)
	}
	if !bp.AllowsForcePushes {
		p.supply(ruleForcePushesBlocked, src)
	}
	if !bp.AllowsDeletions {
		p.supply(ruleDeletionsBlocked, src)
	}
	if bp.RequiresLinearHistory {
		p.supply(ruleLinearHistory, src)
	}
}

func (p *repoProtection) supplyRule(rule github.BranchRule) {
	src := ruleSource{mechanism: rulesetMechanism(rule.RulesetSourceType), rulesetID: rule.RulesetID}
	switch rule.Type {
	case github.RuleTypePullRequest:
		p.supply(rulePullRequestRequired, src)
		if pr := rule.PullRequest; pr != nil {
			p.supplyApprovals(pr.RequiredApprovingReviewCount, src)
			if pr.DismissStaleReviewsOnPush {
				p.supply(ruleDismissStaleReviews, src)
			}
			if pr.RequireCodeOwnerReview {
				p.supply(ruleCodeOwnerReviews, src)
			}
		}
	case github.RuleTypeRequiredStatusChecks:
		p.supply(ruleStatusChecks, src)
	case github.RuleTypeRequiredSignatures:
		p.supply(ruleSignedCommits, src)
	case github.RuleTypeNonFastForward:
		p.supply(ruleForcePushesBlocked, src)
	case github.RuleTypeDeletion:
		p.supply(ruleDeletionsBlocked, src)
	case github.RuleTypeRequiredLinearHistory:
		p.supply(ruleLinearHistory, src)
	}
}

func (p *repoProtection) supply(rule string, src ruleSource) {
	if !slices.Contains(p.supplied[rule], src) {
		p.supplied[rule] = append(p.supplied[rule], src)
	}
}

// supplyApprovals counts approving reviews as required from one approval up.
// The highest count across mechanisms is the effective count, and the
// mechanisms requiring it supply required_approving_review_count.
func (p *repoProtection) supplyApprovals(count int, src ruleSource) {
	if count < 1 {
		return
	}
	p.supply(ruleApprovingReviews, src)
	switch {
	case count > p.approvals:
		p.approvals = count
		p.supplied[ruleRequiredApprovingReviewCount] = []ruleSource{src}
	case count == p.approvals:
		p.supply(ruleRequiredApprovingReviewCount, src)
	}
}

func (p *repoProtection) recordRuleset(rule github.BranchRule, detail *github.Ruleset) {
	for i := range p.rulesets {
		if p.rulesets[i].id == rule.RulesetID {
			if !slices.Contains(p.rulesets[i].ruleTypes, rule.Type) {
				p.rulesets[i].ruleTypes = append(p.rulesets[i].ruleTypes, rule.Type)
			}
			return
		}
	}
	p.rulesets = append(p.rulesets, appliedRuleset{
		id:         rule.RulesetID,
		sourceType: rule.RulesetSourceType,
		source:     rule.RulesetSource,
		ruleTypes:  []string{rule.Type},
		detail:     detail,
	})
}

// state is true when any mechanism supplies the rule, unknown when none does
// but the ruleset rules could not be read, and false otherwise.
func (p *repoProtection) state(rule string) *bool {
	if len(p.supplied[rule]) > 0 {
		return ptr(true)
	}
	if !p.rulesKnown {
		return nil
	}
	return ptr(false)
}

// protected reports whether the default branch has a classic branch
// protection rule or an active ruleset supplying at least one protection rule.
func (p *repoProtection) protected() *bool {
	if p.classic != nil {
		return ptr(true)
	}
	for _, rule := range protectionRules {
		if len(p.supplied[rule]) > 0 {
			return ptr(true)
		}
	}
	if !p.rulesKnown {
		return nil
	}
	return ptr(false)
}

func (p *repoProtection) approvalCount() *int {
	if !p.rulesKnown {
		return nil
	}
	return ptr(p.approvals)
}

// adminEnforcement reports whether administrators are held to every rule on
// the default branch. Administrators are held to a rule when any mechanism
// supplying it applies to them. With no rules, a classic rule's own admin
// setting decides, and an unprotected branch counts as not enforced.
func (p *repoProtection) adminEnforcement() *bool {
	if !p.rulesKnown {
		return nil
	}
	var perRule []*bool
	for _, rule := range protectionRules {
		sources := p.supplied[rule]
		if len(sources) == 0 {
			continue
		}
		held := make([]*bool, 0, len(sources))
		for _, src := range sources {
			held = append(held, p.holdsAdmins(src))
		}
		perRule = append(perRule, anyOf(held...))
	}
	if len(perRule) == 0 {
		return ptr(p.classic != nil && p.classic.IsAdminEnforced)
	}
	return allOf(perRule...)
}

func (p *repoProtection) holdsAdmins(src ruleSource) *bool {
	if src.mechanism == mechanismClassic {
		return ptr(p.classic.IsAdminEnforced)
	}
	for _, rs := range p.rulesets {
		if rs.id == src.rulesetID {
			return rulesetHoldsAdmins(rs.detail)
		}
	}
	return nil
}

// rulesetHoldsAdmins is false when organization admins may bypass the
// ruleset. It is unknown when the bypass list is hidden, or when it names a
// repository role or an actor type this collector does not recognize, because
// GitHub does not document which role a role ID refers to. Team, app, deploy
// key, and user bypasses do not exempt administrators as a role.
func rulesetHoldsAdmins(rs *github.Ruleset) *bool {
	if rs == nil || !rs.BypassVisible {
		return nil
	}
	unknown := false
	for _, a := range rs.BypassActors {
		switch a.ActorType {
		case github.BypassActorOrganizationAdmin:
			return ptr(false)
		case github.BypassActorTeam, github.BypassActorIntegration, github.BypassActorDeployKey, github.BypassActorUser:
		default:
			unknown = true
		}
	}
	if unknown {
		return nil
	}
	return ptr(true)
}

func (p *repoProtection) toEffective() *EffectiveBranchProtection {
	e := &EffectiveBranchProtection{
		Protected:                    p.protected(),
		PullRequestRequired:          p.state(rulePullRequestRequired),
		ApprovingReviews:             p.state(ruleApprovingReviews),
		RequiredApprovingReviewCount: p.approvalCount(),
		DismissStaleReviews:          p.state(ruleDismissStaleReviews),
		CodeOwnerReviews:             p.state(ruleCodeOwnerReviews),
		StatusChecks:                 p.state(ruleStatusChecks),
		SignedCommits:                p.state(ruleSignedCommits),
		ForcePushesBlocked:           p.state(ruleForcePushesBlocked),
		DeletionsBlocked:             p.state(ruleDeletionsBlocked),
		LinearHistory:                p.state(ruleLinearHistory),
		AdminEnforcement:             p.admin,
	}
	for rule, sources := range p.supplied {
		if e.SuppliedBy == nil {
			e.SuppliedBy = map[string][]string{}
		}
		var mechanisms []string
		for _, src := range sources {
			if !slices.Contains(mechanisms, src.mechanism) {
				mechanisms = append(mechanisms, src.mechanism)
			}
		}
		e.SuppliedBy[rule] = mechanisms
	}
	return e
}

func (p *repoProtection) toRulesetRows() []RulesetRow {
	var rows []RulesetRow
	for _, rs := range p.rulesets {
		row := RulesetRow{
			ID:         rs.id,
			SourceType: rs.sourceType,
			Source:     rs.source,
			Rules:      rs.ruleTypes,
		}
		if d := rs.detail; d != nil {
			row.Name = d.Name
			row.Enforcement = d.Enforcement
			if d.BypassVisible {
				row.BypassAllowed = ptr(len(d.BypassActors) > 0)
				for _, a := range d.BypassActors {
					row.BypassActors = append(row.BypassActors, BypassActorRow{
						ActorType:  a.ActorType,
						ActorID:    a.ActorID,
						BypassMode: a.BypassMode,
					})
				}
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// rollupCount is the number of repositories for which value is true. It is
// nil when any value is unknown, because an unknown could fall either way.
func rollupCount(protections []*repoProtection, value func(*repoProtection) *bool) *int {
	count := 0
	for _, p := range protections {
		v := value(p)
		if v == nil {
			return nil
		}
		if *v {
			count++
		}
	}
	return &count
}

// percentOf is count as a percentage of total, rounded down. It is nil when
// count is unknown or total is 0.
func percentOf(count *int, total int) *int {
	if count == nil || total == 0 {
		return nil
	}
	return ptr(percent(*count, total))
}

func ptr[T any](v T) *T {
	return &v
}

// anyOf is true when any value is true, unknown when none is true and some
// are unknown, and false otherwise.
func anyOf(values ...*bool) *bool {
	unknown := false
	for _, v := range values {
		switch {
		case v == nil:
			unknown = true
		case *v:
			return ptr(true)
		}
	}
	if unknown {
		return nil
	}
	return ptr(false)
}

// allOf is false when any value is false, unknown when none is false and some
// are unknown, and true otherwise.
func allOf(values ...*bool) *bool {
	unknown := false
	for _, v := range values {
		switch {
		case v == nil:
			unknown = true
		case !*v:
			return ptr(false)
		}
	}
	if unknown {
		return nil
	}
	return ptr(true)
}
