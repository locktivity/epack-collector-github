package collector

import (
	"fmt"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// protectionRollup is one trust-level branch protection percentage, the
// count of repositories it is taken of, and the per-repository value both
// roll up.
type protectionRollup struct {
	pointer      string
	countPointer string
	value        *int
	state        func(*repoProtection) *bool
	admin        bool
}

func branchProtectionRollups(p *OrgPosture) []protectionRollup {
	rule := func(name string, value *int) protectionRollup {
		return protectionRollup{
			pointer:      "/branch_protection_rules/" + name,
			countPointer: "/branch_protection_rules/repository_counts/" + name,
			value:        value,
			state:        func(rp *repoProtection) *bool { return rp.state(name) },
		}
	}
	r := p.BranchProtectionRules
	return []protectionRollup{
		{"/posture/branch_protection_coverage", "/posture/protected_repository_count", p.Posture.BranchProtectionCoverage, (*repoProtection).protected, false},
		rule(rulePullRequestRequired, r.PullRequestRequired),
		rule(ruleApprovingReviews, r.ApprovingReviews),
		rule(ruleDismissStaleReviews, r.DismissStaleReviews),
		rule(ruleCodeOwnerReviews, r.CodeOwnerReviews),
		rule(ruleStatusChecks, r.StatusChecks),
		rule(ruleSignedCommits, r.SignedCommits),
		{"/branch_protection_rules/admin_enforcement", "/branch_protection_rules/repository_counts/admin_enforcement", r.AdminEnforcement, func(rp *repoProtection) *bool { return rp.admin }, true},
		rule(ruleForcePushesBlocked, r.ForcePushesBlocked),
		rule(ruleDeletionsBlocked, r.DeletionsBlocked),
		rule(ruleLinearHistory, r.LinearHistory),
	}
}

// recordBranchProtectionGaps records why each null branch protection
// percentage is null. A percentage over no repositories needs no gap, and
// neither does an admin enforcement that a bypass actor GitHub does not
// identify leaves undecided; the schema's x-epack-null explains that case.
func (c *Collector) recordBranchProtectionGaps(p *OrgPosture, m *metricsAggregator) {
	if len(m.repos.included) == 0 {
		return
	}
	for _, r := range branchProtectionRollups(p) {
		if r.value != nil {
			continue
		}
		unknown := 0
		var reason error
		for _, repo := range m.repos.included {
			prot := m.repos.protectionFor(repo)
			if r.state(prot) != nil {
				continue
			}
			unknown++
			if reason == nil {
				reason = m.unknownProtectionReason(repoKey(repo), prot, r.admin)
			}
		}
		c.gaps.partial(unknown, reason, r.pointer, r.countPointer)
	}
}

// unknownProtectionReason says why one repository's protection value is
// unknown: its rules could not be read, or, for admin enforcement, a ruleset
// that supplies one of its rules could not be read or hides its bypass list.
// It returns nil when the cause is a bypass actor GitHub does not identify.
func (m *metricsAggregator) unknownProtectionReason(key string, prot *repoProtection, admin bool) error {
	if !prot.rulesKnown {
		return m.branchRulesErrs[key]
	}
	if !admin {
		return nil
	}
	hidden := false
	for _, rule := range protectionRules {
		sources := prot.supplied[rule]
		held := make([]*bool, 0, len(sources))
		for _, src := range sources {
			held = append(held, prot.holdsAdmins(src))
		}
		if len(sources) == 0 || anyOf(held...) != nil {
			continue
		}
		for _, src := range sources {
			if src.mechanism == mechanismClassic {
				continue
			}
			for _, rs := range prot.rulesets {
				switch {
				case rs.id != src.rulesetID:
				case rs.detail == nil:
					return m.rulesetErrs[rs.id]
				case !rs.detail.BypassVisible:
					hidden = true
				}
			}
		}
	}
	if hidden {
		return errBypassHidden
	}
	return nil
}

// maxMechanisms bounds the mechanisms that can supply one rule: classic
// branch protection and repository, organization, and enterprise rulesets.
const maxMechanisms = 4

// recordRepoProtectionGaps records the left-out values of one repository row
// of the repositories surface, at index i.
func (c *Collector) recordRepoProtectionGaps(i int, row RepoRow, prot *repoProtection, m *metricsAggregator) {
	base := fmt.Sprintf("/repositories/per_repo/%d", i)
	eff := row.EffectiveBranchProtection
	effective := base + "/effective_branch_protection"
	key := row.Name

	if !prot.rulesKnown {
		err := m.branchRulesErrs[key]
		for field, value := range effectiveValues(eff) {
			if value {
				continue
			}
			c.gaps.leaveOut(err, effective+"/"+field)
		}
		// Rulesets can add mechanisms to any rule, so the supplied_by entries
		// past the classic rule's are unknown too.
		suppliedBy := effective + "/supplied_by"
		if len(eff.SuppliedBy) == 0 {
			c.gaps.leaveOut(err, suppliedBy)
		} else {
			for _, rule := range append([]string{ruleRequiredApprovingReviewCount}, protectionRules...) {
				mechanisms := eff.SuppliedBy[rule]
				if len(mechanisms) == 0 {
					c.gaps.leaveOut(err, suppliedBy+"/"+rule)
					continue
				}
				for n := len(mechanisms); n < maxMechanisms; n++ {
					c.gaps.leaveOut(err, fmt.Sprintf("%s/%s/%d", suppliedBy, rule, n))
				}
			}
		}
		c.gaps.leaveOut(err, base+"/rulesets")
		return
	}

	if eff.AdminEnforcement == nil {
		c.gaps.leaveOut(m.unknownProtectionReason(key, prot, true), effective+"/admin_enforcement")
	}
	for j, rs := range prot.rulesets {
		ruleset := fmt.Sprintf("%s/rulesets/%d", base, j)
		switch {
		case rs.detail == nil:
			c.gaps.leaveOut(m.rulesetErrs[rs.id], ruleset+"/name", ruleset+"/enforcement", ruleset+"/bypass_allowed", ruleset+"/bypass_actors")
		case !rs.detail.BypassVisible:
			c.gaps.leaveOut(errBypassHidden, ruleset+"/bypass_allowed", ruleset+"/bypass_actors")
		}
	}
}

// effectiveValues maps each effective protection field to whether it is known.
func effectiveValues(e *EffectiveBranchProtection) map[string]bool {
	return map[string]bool{
		"protected":                      e.Protected != nil,
		rulePullRequestRequired:          e.PullRequestRequired != nil,
		ruleApprovingReviews:             e.ApprovingReviews != nil,
		ruleRequiredApprovingReviewCount: e.RequiredApprovingReviewCount != nil,
		ruleDismissStaleReviews:          e.DismissStaleReviews != nil,
		ruleCodeOwnerReviews:             e.CodeOwnerReviews != nil,
		ruleStatusChecks:                 e.StatusChecks != nil,
		ruleSignedCommits:                e.SignedCommits != nil,
		ruleForcePushesBlocked:           e.ForcePushesBlocked != nil,
		ruleDeletionsBlocked:             e.DeletionsBlocked != nil,
		ruleLinearHistory:                e.LinearHistory != nil,
		"admin_enforcement":              e.AdminEnforcement != nil,
	}
}

func repoKey(repo github.Repository) string {
	return repo.Owner.Login + "/" + repo.Name
}
