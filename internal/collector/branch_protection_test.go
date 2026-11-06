package collector

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

func protectedRepo(name string, classic *github.BranchProtectionRule) github.Repository {
	r := github.Repository{Name: name}
	r.Owner.Login = "test-org"
	r.DefaultBranchRef.Name = "main"
	r.DefaultBranchRef.BranchProtectionRule = classic
	return r
}

func orgRule(ruleType string, rulesetID int64) github.BranchRule {
	return github.BranchRule{Type: ruleType, RulesetSourceType: "Organization", RulesetSource: "test-org", RulesetID: rulesetID}
}

func activeRuleset(id int64, actors ...github.BypassActor) *github.Ruleset {
	return &github.Ruleset{ID: id, Enforcement: "active", BypassVisible: true, BypassActors: actors}
}

func describe(v *bool) string {
	if v == nil {
		return "unknown"
	}
	if *v {
		return "true"
	}
	return "false"
}

func TestRulesetHoldsAdmins(t *testing.T) {
	roleID := int64(5)
	tests := []struct {
		name    string
		ruleset *github.Ruleset
		want    string
	}{
		{"ruleset could not be read", nil, "unknown"},
		{"bypass list hidden", &github.Ruleset{Enforcement: "active"}, "unknown"},
		{"no one may bypass", activeRuleset(1), "true"},
		{"non-admin actors only", activeRuleset(1,
			github.BypassActor{ActorType: "Team", ActorID: ptr(int64(42)), BypassMode: "pull_request"},
			github.BypassActor{ActorType: "Integration", ActorID: ptr(int64(7)), BypassMode: "always"},
			github.BypassActor{ActorType: "DeployKey", BypassMode: "always"},
			github.BypassActor{ActorType: "User", ActorID: ptr(int64(9)), BypassMode: "exempt"},
		), "true"},
		{"organization admins may bypass", activeRuleset(1,
			github.BypassActor{ActorType: "OrganizationAdmin", ActorID: ptr(int64(1)), BypassMode: "always"},
		), "false"},
		{"repository role may bypass", activeRuleset(1,
			github.BypassActor{ActorType: "RepositoryRole", ActorID: &roleID, BypassMode: "always"},
		), "unknown"},
		{"organization admins and a repository role", activeRuleset(1,
			github.BypassActor{ActorType: "RepositoryRole", ActorID: &roleID, BypassMode: "always"},
			github.BypassActor{ActorType: "OrganizationAdmin", BypassMode: "pull_request"},
		), "false"},
		{"unrecognized actor type", activeRuleset(1,
			github.BypassActor{ActorType: "EnterpriseOwner", BypassMode: "always"},
		), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describe(rulesetHoldsAdmins(tt.ruleset)); got != tt.want {
				t.Errorf("rulesetHoldsAdmins = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEvaluateProtection_AdminEnforcementIsPerRule(t *testing.T) {
	hidden := map[int64]*github.Ruleset{1: {ID: 1, Enforcement: "active"}}
	noBypass := map[int64]*github.Ruleset{1: activeRuleset(1)}
	classicBlocksPushes := func(adminEnforced bool) *github.BranchProtectionRule {
		return &github.BranchProtectionRule{IsAdminEnforced: adminEnforced}
	}

	tests := []struct {
		name     string
		classic  *github.BranchProtectionRule
		rules    []github.BranchRule
		rulesets map[int64]*github.Ruleset
		want     string
	}{
		{
			name:     "admin-enforced classic rule covers a ruleset with a hidden bypass list",
			classic:  classicBlocksPushes(true),
			rules:    []github.BranchRule{orgRule("non_fast_forward", 1)},
			rulesets: hidden,
			want:     "true",
		},
		{
			name:     "ruleset without bypass covers every rule of a classic rule that exempts admins",
			classic:  classicBlocksPushes(false),
			rules:    []github.BranchRule{orgRule("non_fast_forward", 1), orgRule("deletion", 1)},
			rulesets: noBypass,
			want:     "true",
		},
		{
			name:     "a rule only the admin-exempt classic rule supplies",
			classic:  classicBlocksPushes(false),
			rules:    []github.BranchRule{orgRule("non_fast_forward", 1)},
			rulesets: noBypass,
			want:     "false",
		},
		{
			name:     "ruleset only, bypass list hidden",
			rules:    []github.BranchRule{orgRule("non_fast_forward", 1)},
			rulesets: hidden,
			want:     "unknown",
		},
		{
			name: "unprotected",
			want: "false",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := evaluateProtection(tt.classic, tt.rules, true, tt.rulesets)
			if got := describe(p.admin); got != tt.want {
				t.Errorf("admin enforcement = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEvaluateProtection_ZeroApprovalsIsNotAnApprovingReview(t *testing.T) {
	ruleset := orgRule("pull_request", 1)
	ruleset.PullRequest = &github.PullRequestRuleParameters{RequiredApprovingReviewCount: 0}
	classic := &github.BranchProtectionRule{RequiresApprovingReviews: true, RequiredApprovingReviewCount: 0}

	for name, p := range map[string]*repoProtection{
		"ruleset": evaluateProtection(nil, []github.BranchRule{ruleset}, true, map[int64]*github.Ruleset{1: activeRuleset(1)}),
		"classic": evaluateProtection(classic, nil, true, nil),
	} {
		e := p.toEffective()
		if describe(e.PullRequestRequired) != "true" || describe(e.ApprovingReviews) != "false" {
			t.Errorf("%s: pull_request_required = %s, approving_reviews = %s, want true and false",
				name, describe(e.PullRequestRequired), describe(e.ApprovingReviews))
		}
		if e.RequiredApprovingReviewCount == nil || *e.RequiredApprovingReviewCount != 0 {
			t.Errorf("%s: required_approving_review_count = %v, want 0", name, e.RequiredApprovingReviewCount)
		}
	}
}

func TestEvaluateProtection_EmptyClassicRuleKeepsItsAdminSetting(t *testing.T) {
	classic := &github.BranchProtectionRule{AllowsForcePushes: true, AllowsDeletions: true, IsAdminEnforced: true}
	p := evaluateProtection(classic, nil, true, nil)

	if describe(p.protected()) != "true" || describe(p.admin) != "true" {
		t.Errorf("protected = %s, admin enforcement = %s, want true and true", describe(p.protected()), describe(p.admin))
	}
}

func TestEvaluateProtection_RulesetWithoutProtectionRulesIsNotProtection(t *testing.T) {
	rules := []github.BranchRule{orgRule("creation", 1), orgRule("commit_message_pattern", 1)}
	p := evaluateProtection(nil, rules, true, map[int64]*github.Ruleset{1: activeRuleset(1)})

	if describe(p.protected()) != "false" {
		t.Errorf("protected = %s, want false", describe(p.protected()))
	}
	rows := p.toRulesetRows()
	if len(rows) != 1 || !slices.Equal(rows[0].Rules, []string{"creation", "commit_message_pattern"}) {
		t.Errorf("ruleset rows = %+v, want the ruleset listed with both rules", rows)
	}
}

func TestCollect_RulesetDetailsReadOncePerRuleset(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity:  &github.OrgSecurity{},
		repositories: []github.Repository{protectedRepo("a", nil), protectedRepo("b", nil), protectedRepo("c", nil)},
		branchRules: map[string][]github.BranchRule{
			"test-org/a": {orgRule("deletion", 2001)},
			"test-org/b": {orgRule("deletion", 2001)},
			"test-org/c": {orgRule("deletion", 2001)},
		},
		rulesets: map[int64]*github.Ruleset{2001: activeRuleset(2001)},
	}
	posture, err := NewWithClient(Config{Organization: "test-org"}, mock).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	if !slices.Equal(mock.rulesetRequests, []int64{2001}) {
		t.Errorf("ruleset requests = %v, want one for 2001", mock.rulesetRequests)
	}
	assertPct(t, "deletions_blocked", posture.BranchProtectionRules.DeletionsBlocked, 100)
	assertPct(t, "admin_enforcement", posture.BranchProtectionRules.AdminEnforcement, 100)
}

func TestCollect_UnreadableRulesetKeepsItsRules(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity:  &github.OrgSecurity{},
		repositories: []github.Repository{protectedRepo("a", nil)},
		branchRules:  map[string][]github.BranchRule{"test-org/a": {orgRule("non_fast_forward", 2001)}},
		rulesetErr:   errors.New("ruleset request failed"),
	}
	posture, rec := collectRecorded(t, Config{Organization: "test-org"}, mock, componentsdk.LevelTrust)

	assertPct(t, "branch_protection_coverage", posture.Posture.BranchProtectionCoverage, 100)
	assertPct(t, "force_pushes_blocked", posture.BranchProtectionRules.ForcePushesBlocked, 100)
	if posture.BranchProtectionRules.AdminEnforcement != nil {
		t.Errorf("admin_enforcement = %d, want null", *posture.BranchProtectionRules.AdminEnforcement)
	}
	// The gap records why admin enforcement is unknown, so there is no warning.
	if g := gapOf(rec, "/branch_protection_rules/admin_enforcement"); g == nil || g.Detail != "ruleset request failed" {
		t.Errorf("admin_enforcement gap = %+v, want the unreadable ruleset as its reason", g)
	}
	if len(rec.Warnings()) != 0 {
		t.Errorf("warnings = %+v, want none", rec.Warnings())
	}
}

func TestCollect_FailedRulesReadIsNullWithWarning(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity:    &github.OrgSecurity{},
		repositories:   []github.Repository{protectedRepo("a", nil)},
		branchRulesErr: map[string]error{"test-org/a": errors.New("rules request returned status 502")},
	}
	posture, rec := collectRecorded(t, Config{Organization: "test-org"}, mock, componentsdk.LevelTrust)

	if posture.Posture.BranchProtectionCoverage != nil || posture.BranchProtectionRules.StatusChecks != nil {
		t.Errorf("coverage = %v, status_checks = %v, want null for both",
			posture.Posture.BranchProtectionCoverage, posture.BranchProtectionRules.StatusChecks)
	}
	g := gapOf(rec, "/posture/branch_protection_coverage")
	if g == nil || g.Detail != "rules request returned status 502" || g.MissingPermission != "" || g.Fix != "" {
		t.Errorf("gap = %+v, want the failed read as its reason, with no permission and no fix", g)
	}
	if len(rec.Warnings()) != 0 {
		t.Errorf("warnings = %+v, want none because the gap records the failed read", rec.Warnings())
	}
}

func TestCollect_RepositoryRoleBypassIsExplained(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity:  &github.OrgSecurity{},
		repositories: []github.Repository{protectedRepo("a", nil)},
		branchRules:  map[string][]github.BranchRule{"test-org/a": {orgRule("deletion", 2001)}},
		rulesets: map[int64]*github.Ruleset{2001: activeRuleset(2001,
			github.BypassActor{ActorType: "RepositoryRole", ActorID: ptr(int64(5)), BypassMode: "always"},
		)},
	}
	posture, rec := collectRecorded(t, Config{Organization: "test-org"}, mock, componentsdk.LevelTrust)

	if posture.BranchProtectionRules.AdminEnforcement != nil {
		t.Errorf("admin_enforcement = %d, want null", *posture.BranchProtectionRules.AdminEnforcement)
	}
	if w := warningWith(rec, "a repository role or an unrecognized actor type may bypass 1 of 1 rulesets"); w == nil || !w.NoAction {
		t.Errorf("warnings = %+v, want a warning about the repository-role bypass that needs no action", rec.Warnings())
	}
}

func TestCollect_RepositoryWithoutDefaultBranchSkipsRules(t *testing.T) {
	empty := protectedRepo("empty", nil)
	empty.DefaultBranchRef.Name = ""
	mock := &mockGitHubClient{
		orgSecurity:  &github.OrgSecurity{},
		repositories: []github.Repository{empty},
		branchRules:  map[string][]github.BranchRule{"test-org/empty": {orgRule("deletion", 2001)}},
		rulesets:     map[int64]*github.Ruleset{2001: activeRuleset(2001)},
	}
	posture, err := NewWithClient(Config{Organization: "test-org"}, mock).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	assertPct(t, "branch_protection_coverage", posture.Posture.BranchProtectionCoverage, 0)
	if len(mock.rulesetRequests) != 0 {
		t.Errorf("ruleset requests = %v, want none", mock.rulesetRequests)
	}
}

func TestCollect_NoRepositoriesLeavesBranchMetricsNull(t *testing.T) {
	for name, mock := range map[string]*mockGitHubClient{
		"empty organization":          {orgSecurity: &github.OrgSecurity{}},
		"repository list unavailable": {orgSecurity: &github.OrgSecurity{}, repositoriesErr: errors.New("network timeout")},
	} {
		posture, err := NewWithClient(Config{Organization: "test-org"}, mock).Collect(context.Background(), componentsdk.LevelTrust)
		if err != nil {
			t.Fatalf("%s: Collect() error: %v", name, err)
		}
		if posture.Posture.BranchProtectionCoverage != nil || posture.BranchProtectionRules.PullRequestRequired != nil {
			t.Errorf("%s: coverage = %v, pull_request_required = %v, want null for both",
				name, posture.Posture.BranchProtectionCoverage, posture.BranchProtectionRules.PullRequestRequired)
		}
	}
}

// An empty scope has 0 repositories with each rule or feature, but an
// unreadable repository list leaves the counts unknown.
func TestCollect_CountsAreZeroForNoRepositoriesAndNullForAnUnreadList(t *testing.T) {
	for name, tc := range map[string]struct {
		mock    *mockGitHubClient
		want    *int
		present *bool
	}{
		"empty organization":          {mock: &mockGitHubClient{orgSecurity: &github.OrgSecurity{}}, want: ptr(0), present: ptr(false)},
		"repository list unavailable": {mock: &mockGitHubClient{orgSecurity: &github.OrgSecurity{}, repositoriesErr: errors.New("network timeout")}},
	} {
		for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
			posture, err := NewWithClient(Config{Organization: "test-org"}, tc.mock).Collect(context.Background(), level)
			if err != nil {
				t.Fatalf("%s at %s: Collect() error: %v", name, level, err)
			}
			if got := posture.Scope.RepositoriesPresent; (got == nil) != (tc.present == nil) || got != nil && *got != *tc.present {
				t.Errorf("%s at %s: repositories_present = %v, want %v", name, level, got, tc.present)
			}
			var admin, codeScanning *int
			if c := posture.BranchProtectionRules.RepositoryCounts; c != nil {
				admin = c.AdminEnforcement
			}
			if c := posture.SecurityFeatures.RepositoryCounts; c != nil {
				codeScanning = c.CodeScanning
			}
			want := tc.want
			if level == componentsdk.LevelTrust {
				want = nil // the counts start at the audit level
			}
			for field, got := range map[string]*int{
				"protected_repository_count":                                  posture.Posture.ProtectedRepositoryCount,
				"branch_protection_rules/repository_counts/admin_enforcement": admin,
				"security_features/repository_counts/code_scanning":           codeScanning,
			} {
				switch {
				case want == nil && got != nil:
					t.Errorf("%s at %s: %s = %d, want none", name, level, field, *got)
				case want != nil && (got == nil || *got != *want):
					t.Errorf("%s at %s: %s = %v, want %d", name, level, field, got, *want)
				}
			}
		}
	}
}
