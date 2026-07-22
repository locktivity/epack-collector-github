package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// richMock returns a mock populated across every surface, for two repos.
func richMock() *mockGitHubClient {
	repo := func(name, vis string) github.Repository {
		r := github.Repository{Name: name, Visibility: vis}
		r.Owner.Login = "test-org"
		r.DefaultBranchRef.Name = "main"
		r.DefaultBranchRef.BranchProtectionRule = &github.BranchProtectionRule{
			RequiresApprovingReviews:     true,
			RequiredApprovingReviewCount: 2,
		}
		r.HasVulnerabilityAlertsEnabled = true
		return r
	}
	return &mockGitHubClient{
		orgSecurity:  &github.OrgSecurity{TwoFactorRequired: boolPtr(true)},
		repositories: []github.Repository{repo("repo1", "PRIVATE"), repo("repo2", "PUBLIC")},
		securitySettings: map[string]*github.SecuritySettings{
			"test-org/repo1": {SecretScanning: true, CodeScanningEnabled: true},
			"test-org/repo2": {DependabotSecurityUpdates: true},
		},
		orgSettings: &github.OrgSettings{DefaultRepositoryPermission: "read", MembersCanCreateRepositories: boolPtr(false)},
		alertCounts: map[string]*github.AlertCounts{
			"test-org/repo1": {SecretScanningOpen: 3, CodeScanningOpen: 1},
		},
		secretAlerts: map[string][]github.SecretScanningAlert{
			"test-org/repo1": {{Number: 1, SecretType: "aws_key", State: "open", CreatedAt: "2026-05-01T00:00:00Z"}},
		},
		codeAlerts: map[string][]github.CodeScanningAlert{
			"test-org/repo1": {{Number: 2, RuleID: "js/sqli", Severity: "high", State: "open", CreatedAt: "2026-05-02T00:00:00Z"}},
		},
		membership: &github.OrgMembership{
			Members:              []string{"alice", "bob"},
			Admins:               []string{"alice"},
			OutsideCollaborators: []string{"carol"},
			TwoFADisabled:        map[string]bool{"bob": true},
			PendingInvitations:   1,
			Names:                map[string]string{"alice": "Alice Adams", "carol": "Carol Chen"},
		},
		codeowners: map[string]codeownersFixture{
			"test-org/repo1": {present: true, path: ".github/CODEOWNERS", hash: "abc123"},
		},
		orgHooks: []github.Hook{{ID: 1, Active: true, Events: []string{"push"}, URLHost: "hooks.example.com"}},
		repoHooks: map[string][]github.Hook{
			"test-org/repo1": {{ID: 2, Active: true, Events: []string{"pull_request"}, URLHost: "ci.example.com"}},
		},
		deployKeys: map[string][]github.DeployKey{
			"test-org/repo1": {{ID: 3, Title: "deploy", ReadOnly: false, Fingerprint: "ff:ee"}},
		},
		orgRunners:  []github.Runner{{ID: 10, Name: "runner-1", OS: "linux", Status: "online"}},
		repoRunners: map[string][]github.Runner{"test-org/repo1": {{ID: 11, Name: "repo-runner", OS: "linux"}}},
		secretNames: []string{"DEPLOY_TOKEN"},
		auditEvents: []github.AuditEvent{
			{Action: "repo.create", Actor: "alice", Repo: "test-org/repo1", CreatedAt: 1700000000},
			{Action: "member_add", Actor: "bob", CreatedAt: 1700000100},
		},
		installations: []github.Installation{
			{AppSlug: "dependabot", AppID: 99, Permissions: map[string]string{"metadata": "read"}, CreatedAt: "2026-01-01T00:00:00Z"},
		},
		pats: []github.PATGrant{
			{ID: 5, Owner: "alice", TokenName: "ci-token", Permissions: []string{"contents:read"}, ExpiresAt: "2026-12-01T00:00:00Z"},
		},
	}
}

func collectAt(t *testing.T, level componentsdk.Level) *OrgPosture {
	t.Helper()
	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, richMock())
	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture
}

func TestSurfaces_TrustOmitsAllNewSurfaces(t *testing.T) {
	p := collectAt(t, componentsdk.LevelTrust)

	if p.CollectedAtLevel != "trust" {
		t.Errorf("collected_at_level = %q, want trust", p.CollectedAtLevel)
	}
	if p.Members != nil || p.Repositories != nil || p.Codeowners != nil ||
		p.Webhooks != nil || p.DeployKeys != nil || p.Actions != nil ||
		p.AuditLog != nil || p.Apps != nil || p.Tokens != nil {
		t.Error("trust must not populate any new surface")
	}
	if p.SecurityFeatures.PerRepo != nil || p.SecurityFeatures.Findings != nil {
		t.Error("trust must not populate SecurityFeatures.PerRepo or Findings")
	}
	if p.AccessControl.DefaultRepositoryPermission != "" {
		t.Error("trust must not populate audit AccessControl fields")
	}
}

func TestSurfaces_AuditPopulatesNoInternalDetail(t *testing.T) {
	p := collectAt(t, componentsdk.LevelAudit)

	if p.CollectedAtLevel != "audit" {
		t.Errorf("collected_at_level = %q, want audit", p.CollectedAtLevel)
	}
	if p.Members == nil || p.Members.MemberCount != 2 || p.Members.AdminCount != 1 {
		t.Fatalf("members audit counts wrong: %+v", p.Members)
	}
	// Audit has per-member login/name/role but no 2FA flag.
	names := map[string]string{}
	for _, m := range p.Members.PerMember {
		if m.TwoFactorEnabled != nil {
			t.Error("audit must not include per-member 2FA")
		}
		names[m.Login] = m.Name
	}
	if names["alice"] != "Alice Adams" || names["bob"] != "" || names["carol"] != "Carol Chen" {
		t.Errorf("per-member names wrong: %v", names)
	}
	if p.Repositories == nil || p.Repositories.TotalCount != 2 || p.Repositories.PrivateCount != 1 {
		t.Fatalf("repositories audit wrong: %+v", p.Repositories)
	}
	if len(p.Repositories.PerRepo) == 0 || p.Repositories.PerRepo[0].BranchProtection == nil {
		t.Error("audit repos should carry branch-protection detail")
	}
	if p.Repositories.PerRepo[0].Description != "" {
		t.Error("audit must not include repo description (internal-only)")
	}
	if p.SecurityFeatures.PerRepo == nil {
		t.Error("audit should populate SecurityFeatures.PerRepo")
	}
	if p.SecurityFeatures.Findings != nil {
		t.Error("audit must not populate findings inventory")
	}
	if p.Webhooks == nil || p.Webhooks.OrgCount != 1 || len(p.Webhooks.Org) != 0 {
		t.Errorf("audit webhooks should have counts but no rows: %+v", p.Webhooks)
	}
	if p.Codeowners == nil || len(p.Codeowners.PerRepo) == 0 {
		t.Fatal("audit should populate codeowners presence")
	}
	if p.Codeowners.PerRepo[0].Hash != "" {
		t.Error("audit must not include CODEOWNERS hash (internal-only)")
	}
	if p.Tokens == nil || p.Tokens.GrantCount != 1 || len(p.Tokens.PerToken) != 0 {
		t.Errorf("audit tokens should have count but no rows: %+v", p.Tokens)
	}
}

func TestSurfaces_InternalIncludesEverything(t *testing.T) {
	p := collectAt(t, componentsdk.LevelInternal)

	if p.CollectedAtLevel != "internal" {
		t.Errorf("collected_at_level = %q, want internal", p.CollectedAtLevel)
	}
	if p.SecurityFeatures.Findings == nil || len(p.SecurityFeatures.Findings.SecretScanning) == 0 {
		t.Error("internal should populate findings inventory")
	}
	// Per-member 2FA: bob is in the disabled set, alice is not.
	var sawAlice, sawBob bool
	for _, m := range p.Members.PerMember {
		if m.Login == "alice" && (m.TwoFactorEnabled == nil || !*m.TwoFactorEnabled) {
			t.Error("alice should have 2FA enabled")
		}
		if m.Login == "bob" && (m.TwoFactorEnabled == nil || *m.TwoFactorEnabled) {
			t.Error("bob should have 2FA disabled")
		}
		if m.Login == "alice" {
			sawAlice = true
			if m.LastActivity == "" {
				t.Error("alice should have last-activity from audit log")
			}
		}
		if m.Login == "bob" {
			sawBob = true
		}
	}
	if !sawAlice || !sawBob {
		t.Error("expected alice and bob in per-member rows")
	}
	if p.Codeowners.PerRepo[0].Hash == "" {
		t.Error("internal should include CODEOWNERS hash")
	}
	if len(p.Webhooks.Org) == 0 {
		t.Error("internal should include webhook rows")
	}
	if p.AuditLog == nil || len(p.AuditLog.Events) == 0 {
		t.Error("internal should include audit-log events")
	}
	if p.Tokens == nil || len(p.Tokens.PerToken) == 0 {
		t.Error("internal should include per-token rows")
	}
	if len(p.DeployKeys.PerKey) == 0 {
		t.Error("internal should include deploy-key rows")
	}
}

func TestSurfaces_MemberLastActivityCorrelatesWithAuditLog(t *testing.T) {
	// Characterizes the cross-surface correlation: a member's last_activity is
	// the most recent audit-log event timestamp for that actor. richMock's audit
	// events: alice@1700000000 (repo.create), bob@1700000100 (member_add).
	p := collectAt(t, componentsdk.LevelInternal)

	got := map[string]string{}
	for _, m := range p.Members.PerMember {
		got[m.Login] = m.LastActivity
	}

	want := map[string]string{
		"alice": "2023-11-14T22:13:20Z", // time.Unix(1700000000, 0).UTC()
		"bob":   "2023-11-14T22:15:00Z", // time.Unix(1700000100, 0).UTC()
	}
	for login, ts := range want {
		if got[login] != ts {
			t.Errorf("member %s LastActivity = %q, want %q", login, got[login], ts)
		}
	}
	// carol (outside collaborator) has no audit-log event → no last activity.
	if got["carol"] != "" {
		t.Errorf("carol LastActivity = %q, want empty", got["carol"])
	}
}

func TestSurfaces_NeverEmitsForbiddenData(t *testing.T) {
	p := collectAt(t, componentsdk.LevelInternal)
	jsonBytes, _ := json.Marshal(p)
	out := string(jsonBytes)

	// Webhook URL host only: no scheme/path leakage.
	for _, h := range p.Webhooks.Org {
		if strings.Contains(h.URLHost, "/") || strings.Contains(h.URLHost, "https:") {
			t.Errorf("webhook url_host leaked path/scheme: %q", h.URLHost)
		}
	}
	// Deploy keys: fingerprint, never a raw key field.
	if strings.Contains(out, `"key"`) {
		t.Error("deploy key raw key must never be emitted")
	}
	// Tokens: no token value field.
	if strings.Contains(out, `"token":`) {
		t.Error("PAT token value must never be emitted")
	}
}

func TestSurfaces_AuditLogDegradesOnNonEnterprise(t *testing.T) {
	mock := richMock()
	mock.auditErr = github.ErrFeatureUnavailable

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if p.AuditLog != nil {
		t.Error("audit log should be nil on non-Enterprise org")
	}
	if p.Diagnostics == nil || len(p.Diagnostics.Warnings) == 0 {
		t.Fatal("expected an audit-log feature-unavailable warning")
	}
	if !anyContains(p.Diagnostics.Warnings, "audit_log") {
		t.Errorf("warnings = %v, want one naming audit_log", p.Diagnostics.Warnings)
	}
}

func TestSurfaces_TokensDegradeWithoutFGTPolicy(t *testing.T) {
	mock := richMock()
	mock.patsErr = github.ErrFeatureUnavailable

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelInternal)
	if p.Tokens != nil {
		t.Error("tokens should be nil without FGT policy")
	}
	if p.Diagnostics == nil || !anyContains(p.Diagnostics.Warnings, "tokens") {
		t.Errorf("expected a tokens feature-unavailable warning, got %+v", p.Diagnostics)
	}
}

func TestSurfaces_AlertFeatureDisabledIsWarning(t *testing.T) {
	// A feature-not-enabled 403 on the alert endpoints must degrade to a warning,
	// not a permission_error telling the customer to grant a scope they may have.
	mock := richMock()
	mock.alertCountsErr = github.ErrFeatureUnavailable
	mock.alertListErr = github.ErrFeatureUnavailable

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelInternal)

	if p.Diagnostics == nil {
		t.Fatal("expected diagnostics")
	}
	if anyContains(p.Diagnostics.PermissionErrors, "security_features.alert_counts") ||
		anyContains(p.Diagnostics.PermissionErrors, "security_features.findings") {
		t.Errorf("feature-disabled should not be a permission_error: %v", p.Diagnostics.PermissionErrors)
	}
	if !anyContains(p.Diagnostics.Warnings, "security_features.alert_counts") {
		t.Errorf("expected an alert_counts warning, got %v", p.Diagnostics.Warnings)
	}
	if !anyContains(p.Diagnostics.Warnings, "security_features.findings") {
		t.Errorf("expected a findings warning, got %v", p.Diagnostics.Warnings)
	}
}

func TestSurfaces_AlertPermissionDeniedStillErrors(t *testing.T) {
	// A genuine permission denial on the alert endpoints stays a permission_error.
	mock := richMock()
	mock.alertCountsErr = github.ErrPermissionDenied

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelAudit)

	if p.Diagnostics == nil || !anyContains(p.Diagnostics.PermissionErrors, "security_features.alert_counts") {
		t.Errorf("expected an alert_counts permission_error, got %+v", p.Diagnostics)
	}
}

func TestSurfaces_MembersPermissionDenied(t *testing.T) {
	mock := richMock()
	mock.membershipErr = github.ErrPermissionDenied

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelAudit)
	if p.Members != nil {
		t.Error("members should be nil on permission denial")
	}
	if p.Diagnostics == nil || !anyContains(p.Diagnostics.PermissionErrors, "members") {
		t.Errorf("expected a members permission diagnostic, got %+v", p.Diagnostics)
	}
}

func TestSurfaces_MemberNameGapsRecordWarning(t *testing.T) {
	mock := richMock()
	mock.membership.NamesIncomplete = []string{"outside-collaborator name lookups capped at 200 of 205"}

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelAudit)
	if p.Diagnostics == nil || !anyContains(p.Diagnostics.Warnings, "display names incomplete") {
		t.Errorf("expected a member-names warning, got %+v", p.Diagnostics)
	}
}

func TestSurfaces_MembersTruncation(t *testing.T) {
	mock := richMock()
	logins := make([]string, MembersCap+5)
	for i := range logins {
		logins[i] = fmt.Sprintf("user%05d", i)
	}
	mock.membership = &github.OrgMembership{Members: logins}

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelAudit)
	if p.Members == nil || !p.Members.Truncated {
		t.Fatal("expected members truncation flag")
	}
	if p.Members.TruncatedDropped != 5 {
		t.Errorf("dropped = %d, want 5", p.Members.TruncatedDropped)
	}
	if len(p.Members.PerMember) != MembersCap {
		t.Errorf("per-member len = %d, want %d", len(p.Members.PerMember), MembersCap)
	}
}

func anyContains(items []string, sub string) bool {
	for _, i := range items {
		if strings.Contains(i, sub) {
			return true
		}
	}
	return false
}
