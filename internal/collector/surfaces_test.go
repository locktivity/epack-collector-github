package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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
		orgSecurity:  &github.OrgSecurity{TwoFactorRequired: boolPtr(true), DefaultRepositoryPermission: "read"},
		repositories: []github.Repository{repo("repo1", "PRIVATE"), repo("repo2", "PUBLIC")},
		securitySettings: map[string]*github.SecuritySettings{
			"test-org/repo1": {SecretScanning: true, CodeScanningEnabled: true},
			"test-org/repo2": {DependabotSecurityUpdates: true},
		},
		orgSettings: &github.OrgSettings{DefaultRepositoryPermission: "read", MembersCanCreateRepositories: boolPtr(false)},
		secretAlerts: map[string][]github.SecretScanningAlert{
			"test-org/repo1": {{Number: 1, SecretType: "aws_key", State: "open", CreatedAt: "2026-05-01T00:00:00Z"}},
		},
		codeAlerts: map[string][]github.CodeScanningAlert{
			"test-org/repo1": {{Number: 2, RuleID: "js/sqli", Severity: "high", State: "open", CreatedAt: "2026-05-02T00:00:00Z"}},
		},
		membership: &github.OrgMembership{
			Members:                    []string{"alice", "bob"},
			Admins:                     []string{"alice"},
			OutsideCollaborators:       []string{"carol"},
			TwoFADisabled:              map[string]bool{"bob": true},
			CollaboratorsTwoFADisabled: map[string]bool{},
			PendingInvitations:         1,
			Names:                      map[string]string{"alice": "Alice Adams", "carol": "Carol Chen"},
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
		environments: map[string][]github.Environment{
			"test-org/repo1": {
				{
					Name:                 "production",
					HasRequiredReviewers: true,
					PreventSelfReview:    true,
					Reviewers: []github.EnvironmentReviewer{
						{Type: "Team", Slug: "release-approvers", Name: "Release Approvers"},
						{Type: "User", Login: "alice"},
					},
					WaitTimerMinutes: 30,
					BranchPolicy:     github.BranchPolicyProtected,
					CanAdminsBypass:  boolPtr(true),
					CreatedAt:        "2026-02-01T00:00:00Z",
				},
				{Name: "staging", BranchPolicy: github.BranchPolicyCustom},
			},
		},
		envPatterns: map[string][]github.BranchPolicyPattern{
			"test-org/repo1#staging": {{Name: "release/*", Type: "branch"}},
		},
		envApps: map[string][]string{
			"test-org/repo1#production": {"deploy-gate"},
		},
		auditEvents: []github.AuditEvent{
			{Action: "repo.create", Actor: "alice", Repo: "test-org/repo1", CreatedAt: 1700000000000},
			{Action: "org.add_member", Actor: "bob", CreatedAt: 1700000100000},
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
		p.Environments != nil || p.AuditLog != nil || p.Apps != nil || p.Tokens != nil {
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
	if p.Members == nil || p.Members.MemberCount == nil || *p.Members.MemberCount != 2 || p.Members.AdminCount == nil || *p.Members.AdminCount != 1 {
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
	if p.Webhooks == nil || p.Webhooks.OrgCount == nil || *p.Webhooks.OrgCount != 1 || len(p.Webhooks.Org) != 0 {
		t.Errorf("audit webhooks should have counts but no rows: %+v", p.Webhooks)
	}
	if p.Codeowners == nil || len(p.Codeowners.PerRepo) == 0 {
		t.Fatal("audit should populate codeowners presence")
	}
	if p.Codeowners.PerRepo[0].Hash != "" {
		t.Error("audit must not include CODEOWNERS hash (internal-only)")
	}
	if p.Tokens == nil || p.Tokens.GrantCount == nil || *p.Tokens.GrantCount != 1 || len(p.Tokens.PerToken) != 0 {
		t.Errorf("audit tokens should have count but no rows: %+v", p.Tokens)
	}
	if p.Environments == nil || p.Environments.TotalCount == nil || *p.Environments.TotalCount != 2 ||
		p.Environments.WithRequiredReviewersCount == nil || *p.Environments.WithRequiredReviewersCount != 1 {
		t.Fatalf("environments audit counts wrong: %+v", p.Environments)
	}
	envs := map[string]EnvironmentRow{}
	for _, row := range p.Environments.PerEnvironment {
		envs[row.Name] = row
	}
	prod := envs["production"]
	if !prod.RequiresReviewers || !prod.PreventSelfReview || prod.WaitTimerMinutes != 30 {
		t.Errorf("production gate config wrong: %+v", prod)
	}
	if len(prod.Reviewers) != 2 || prod.Reviewers[0].Slug != "release-approvers" || prod.Reviewers[1].Login != "alice" {
		t.Errorf("production reviewers wrong: %+v", prod.Reviewers)
	}
	if prod.BranchPolicy != "protected_branches" || prod.CanAdminsBypass == nil || !*prod.CanAdminsBypass {
		t.Errorf("production branch policy / bypass wrong: %+v", prod)
	}
	if len(prod.ProtectionApps) != 1 || prod.ProtectionApps[0] != "deploy-gate" {
		t.Errorf("production protection apps wrong: %+v", prod.ProtectionApps)
	}
	staging := envs["staging"]
	if staging.BranchPolicy != "custom" || len(staging.BranchPolicyPatterns) != 1 || staging.BranchPolicyPatterns[0].Name != "release/*" {
		t.Errorf("staging custom branch patterns wrong: %+v", staging)
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
	// events: alice@1700000000 (repo.create), bob@1700000100 (org.add_member).
	p := collectAt(t, componentsdk.LevelInternal)

	got := map[string]string{}
	for _, m := range p.Members.PerMember {
		got[m.Login] = m.LastActivity
	}

	want := map[string]string{
		"alice": "2023-11-14T22:13:20Z", // time.UnixMilli(1700000000000).UTC()
		"bob":   "2023-11-14T22:15:00Z", // time.UnixMilli(1700000100000).UTC()
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

func TestSurfaces_MemberLastActivityFromACutAuditLog(t *testing.T) {
	// The audit log is read newest first, up to AuditLogCap events. A person
	// with no event among those read can have an older one in the window, so
	// their last activity is left out with a gap.
	mock := richMock()
	mock.auditEvents = []github.AuditEvent{{Action: "repo.create", Actor: "alice", Repo: "test-org/repo1", CreatedAt: 1700000000000}}
	mock.auditMore = true

	p, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelInternal)
	for i, m := range p.Members.PerMember {
		gap := gapOf(rec, rowPointer("/members/per_member", i, "last_activity"))
		read := m.Login == "alice"
		if read != (m.LastActivity != "") || read != (gap == nil) {
			t.Errorf("%s: last_activity %q, gap %+v; want a time and no gap only for alice, whose event was read", m.Login, m.LastActivity, gap)
		}
		if gap != nil && gap.Code != componentsdk.CodeTooLarge {
			t.Errorf("%s: gap code %s, want too_large, since the log holds more events than the collector reads", m.Login, gap.Code)
		}
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

	p, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelInternal)
	if p.AuditLog != nil {
		t.Error("audit log should be nil on non-Enterprise org")
	}
	if w := warningWith(rec, "audit_log"); w != nil {
		t.Errorf("warning %q, want none because the gap covers the missing audit log", w.Message)
	}
	// The gap gives the customer a choice of plan for the audit log.
	if g := gapOf(rec, "/audit_log"); g == nil || g.Choice == nil || len(g.Choice.Options) != 2 || g.Fix != "" {
		t.Errorf("audit_log gap = %+v, want a choice of plan", g)
	}
}

// A created:>= date with no time means the start of that day, so the read
// includes the time of day.
func TestSurfaces_AuditLogWindowStartsSevenDaysBeforeCollection(t *testing.T) {
	mock := richMock()
	now := time.Date(2026, 10, 17, 12, 30, 5, 0, time.UTC)
	collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}, Now: func() time.Time { return now }}, mock, componentsdk.LevelAudit)
	if want := "2026-10-10T12:30:05+00:00"; mock.auditSince != want {
		t.Errorf("audit log read starts at %q, want %q", mock.auditSince, want)
	}
}

func TestSurfaces_TokensDegradeWithoutFGTPolicy(t *testing.T) {
	mock := richMock()
	mock.patsErr = github.ErrFeatureUnavailable

	p, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelInternal)
	if p.Tokens != nil {
		t.Error("tokens should be nil without FGT policy")
	}
	if g := gapOf(rec, "/tokens"); g == nil || g.Detail != "feature unavailable" {
		t.Errorf("tokens gap = %+v, want the unavailable feature as its reason", g)
	}
}

func TestSurfaces_AlertFeatureDisabledIsWarning(t *testing.T) {
	// A feature-not-enabled 403 on the alert endpoints must degrade to a warning,
	// not a permission_error telling the customer to grant a scope they may have.
	mock := richMock()
	mock.alertListErr = github.ErrFeatureUnavailable

	_, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelInternal)

	for _, g := range rec.Gaps() {
		if g.MissingPermission != "" {
			t.Errorf("gap %s has missing permission %s, want none for a feature turned off", g.Pointer, g.MissingPermission)
		}
	}
	for _, surface := range []string{"security_features.alert_counts", "security_features.findings"} {
		if w := warningWith(rec, "surface "+surface+":"); w == nil || !w.NoAction {
			t.Errorf("warnings = %+v, want one for %s that needs no action", rec.Warnings(), surface)
		}
	}
}

func TestSurfaces_AlertPermissionDeniedStillErrors(t *testing.T) {
	// A genuine permission denial on the alert endpoints stays a permission_error.
	mock := richMock()
	mock.alertListErr = github.ErrPermissionDenied

	_, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelAudit)

	denied := 0
	for _, g := range rec.Gaps() {
		if strings.HasPrefix(g.Pointer, "/security_features/per_repo/") && g.Detail == "permission denied" {
			denied++
		}
	}
	if denied == 0 {
		t.Errorf("gaps = %+v, want the refused alert counts left out with the refusal as their reason", rec.Gaps())
	}
}

func TestSurfaces_AlertListAtTheCapLeavesItsCountOut(t *testing.T) {
	// A list that reaches the fetch cap may hold more alerts than it read, so
	// its count is null, as the schema's x-epack-null explains, rather than the
	// number read.
	mock := richMock()
	mock.alertListMore = true
	rec := &componentsdk.Recorder{}

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, Recorder: rec}, mock)
	p, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatal(err)
	}
	row := p.SecurityFeatures.PerRepo[0]
	if row.OpenSecretScanningAlerts != nil || row.OpenCodeScanningAlerts != nil || row.OpenDependabotAlerts != nil {
		t.Errorf("counts = %v, %v, %v; want null", row.OpenSecretScanningAlerts, row.OpenCodeScanningAlerts, row.OpenDependabotAlerts)
	}
	if !p.SecurityFeatures.Findings.Truncated {
		t.Error("findings should be flagged as cut short")
	}
	for _, g := range rec.Gaps() {
		if strings.HasPrefix(g.Pointer, "/security_features/") {
			t.Errorf("unexpected gap %+v: a list cut short is not a failure", g)
		}
	}
}

func TestSurfaces_InventoryListsAtTheCapLeaveTheirCountsOut(t *testing.T) {
	// A roster, webhook, deploy key, or token list that reaches its fetch cap
	// may hold more than it read, so its counts are null, as the schema's
	// x-epack-null explains, and the rows it read are flagged as cut short.
	mock := richMock()
	mock.membership.MembersMore = true
	mock.membership.AdminsMore = true
	mock.membership.OutsideCollaboratorsMore = true
	mock.hooksMore = true
	mock.deployKeysMore = true
	mock.patsMore = true
	collect := func(level componentsdk.Level) (*OrgPosture, []componentsdk.Gap) {
		rec := &componentsdk.Recorder{}
		p, err := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, Recorder: rec}, mock).Collect(context.Background(), level)
		if err != nil {
			t.Fatal(err)
		}
		return p, rec.Gaps()
	}

	p, gaps := collect(componentsdk.LevelInternal)
	if m := p.Members; m.MemberCount != nil || m.AdminCount != nil || m.OutsideCollaboratorCount != nil || len(m.PerMember) != 3 || !m.Truncated {
		t.Errorf("members = %+v, want null counts and the rows read, flagged", m)
	}
	if w := p.Webhooks; w.OrgCount != nil || w.RepoCount != nil || w.CountByEvent != nil || len(w.Org) != 1 || len(w.Repo) != 1 || !w.Truncated {
		t.Errorf("webhooks = %+v, want null counts, no breakdown, and the rows read, flagged", w)
	}
	if dk := p.DeployKeys; dk.TotalCount != nil || dk.ReadWriteCount != nil || len(dk.PerKey) != 1 || !dk.Truncated {
		t.Errorf("deploy keys = %+v, want null counts and the rows read, flagged", dk)
	}
	if tk := p.Tokens; tk.GrantCount != nil || len(tk.PerToken) != 1 || !tk.Truncated {
		t.Errorf("tokens = %+v, want a null count and the rows read, flagged", tk)
	}
	for _, g := range gaps {
		for _, surface := range []string{"/members", "/webhooks", "/deploy_keys", "/tokens"} {
			if g.Pointer == surface || strings.HasPrefix(g.Pointer, surface+"/") {
				t.Errorf("unexpected gap %+v: a list cut short is not a failure", g)
			}
		}
	}

	p, _ = collect(componentsdk.LevelAudit)
	if p.Webhooks.OrgCount != nil || p.DeployKeys.TotalCount != nil || p.Tokens.GrantCount != nil {
		t.Errorf("audit counts = %v, %v, %v; want null", p.Webhooks.OrgCount, p.DeployKeys.TotalCount, p.Tokens.GrantCount)
	}
	if p.Webhooks.Truncated || p.DeployKeys.Truncated || p.Tokens.Truncated {
		t.Error("audit emits no webhook, deploy key, or token rows, so it should flag none")
	}
}

func TestSurfaces_ArchivedCountCoversTheOrganization(t *testing.T) {
	// Archived repositories are never in scope, so the count comes from the
	// whole repository list, patterns or not, rather than from the rows.
	mock := richMock()
	archived := mock.repositories[0]
	archived.Name, archived.IsArchived = "old-app", true
	excluded := archived
	excluded.Name = "sandbox-old"
	mock.repositories = append(mock.repositories, archived, excluded)

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, ExcludePatterns: []string{"sandbox-*"}}, mock)
	p, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	if r := p.Repositories; r.ArchivedCount != 2 || r.TotalCount != 2 || len(r.PerRepo) != 2 {
		t.Errorf("repositories = %d archived, %d in scope, %d rows; want 2, 2, 2", r.ArchivedCount, r.TotalCount, len(r.PerRepo))
	}
}

func TestSurfaces_MembersPermissionDenied(t *testing.T) {
	mock := richMock()
	mock.membershipErr = github.ErrPermissionDenied

	p, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelAudit)
	if p.Members != nil {
		t.Error("members should be nil on permission denial")
	}
	if gapOf(rec, "/members") == nil {
		t.Error("members have no gap")
	}
}

func TestSurfaces_MemberNameGapsRecordWarning(t *testing.T) {
	mock := richMock()
	mock.membership.NamesIncomplete = []string{"outside-collaborator name lookups capped at 200 of 205"}

	_, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelAudit)
	if w := warningWith(rec, "display names incomplete"); w == nil || !w.NoAction {
		t.Errorf("warnings = %+v, want a member-names warning that needs no action", rec.Warnings())
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

func TestSurfaces_MembersTruncationKeepsMembersWhenTheOwnerRosterIsUnreadable(t *testing.T) {
	// Without the owner roster the members have no role. They are still kept
	// ahead of outside collaborators at the cap.
	mock := richMock()
	logins := make([]string, MembersCap)
	for i := range logins {
		logins[i] = fmt.Sprintf("member%05d", i)
	}
	mock.membership = &github.OrgMembership{
		Members:              logins,
		AdminsErr:            github.ErrPermissionDenied,
		OutsideCollaborators: []string{"aaa-outside"},
	}

	p, _ := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelAudit)
	for _, row := range p.Members.PerMember {
		if row.Role == "outside_collaborator" {
			t.Fatalf("kept outside collaborator %s while members were dropped", row.Login)
		}
	}
	if p.Members.TruncatedDropped != 1 {
		t.Errorf("dropped = %d, want 1", p.Members.TruncatedDropped)
	}
}

func TestSurfaces_EnvironmentsPermissionDenied(t *testing.T) {
	// A denied environment list leaves the counts and rows out, rather than
	// reporting zero environments.
	mock := richMock()
	mock.environmentsErr = github.ErrPermissionDenied

	p, rec := collectRecorded(t, Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock, componentsdk.LevelAudit)
	if p.Environments == nil || p.Environments.TotalCount != nil || p.Environments.WithRequiredReviewersCount != nil || p.Environments.PerEnvironment != nil {
		t.Errorf("denied environments should leave counts and rows out: %+v", p.Environments)
	}
	if gapOf(rec, "/environments/total_count") == nil {
		t.Error("environments total_count has no gap")
	}
}

func TestSurfaces_EnvironmentsFetchCapCountsDropped(t *testing.T) {
	// A repo whose environment fetch was capped reports the full total and
	// flags the gap, so a partial list never reads as complete.
	mock := richMock()
	mock.environmentTotals = map[string]int{"test-org/repo1": 5}

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelAudit)
	if p.Environments.TotalCount == nil || *p.Environments.TotalCount != 5 {
		t.Errorf("TotalCount = %v, want 5 (the reported total)", p.Environments.TotalCount)
	}
	if !p.Environments.Truncated || p.Environments.TruncatedDropped != 3 {
		t.Errorf("truncation = %v/%d, want true/3", p.Environments.Truncated, p.Environments.TruncatedDropped)
	}
	if len(p.Environments.PerEnvironment) != 2 {
		t.Errorf("row count = %d, want 2", len(p.Environments.PerEnvironment))
	}
}

func TestSurfaces_InventoryCountsAreGitHubTotals(t *testing.T) {
	// A runner or installation list read short of its total, as at the fetch
	// cap, reports GitHub's total and flags the rows as cut short.
	mock := richMock()
	mock.orgRunnerTotal = 12000
	mock.installationTotal = 150
	collect := func(level componentsdk.Level) *OrgPosture {
		p, err := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock).Collect(context.Background(), level)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	p := collect(componentsdk.LevelInternal)
	if a := p.Actions; a.OrgRunnerCount == nil || *a.OrgRunnerCount != 12000 || len(a.OrgRunners) != 1 || !a.Truncated {
		t.Errorf("internal actions = %+v, want the total of 12000 over 1 row, flagged", a)
	}
	if apps := p.Apps; apps.InstallationCount != 150 || len(apps.PerInstallation) != 1 || !apps.Truncated {
		t.Errorf("apps = %+v, want the total of 150 over 1 row, flagged", apps)
	}

	p = collect(componentsdk.LevelAudit)
	if a := p.Actions; a.OrgRunnerCount == nil || *a.OrgRunnerCount != 12000 || a.Truncated {
		t.Errorf("audit actions = %+v, want the total, and no flag for rows audit does not emit", a)
	}
}

func TestSurfaces_EnvironmentsCapKeepsReviewerGated(t *testing.T) {
	// Build more environments than the org-wide cap, with the single
	// reviewer-gated one sorted last alphabetically. The cap must keep it.
	mock := richMock()
	envs := make([]github.Environment, 0, EnvironmentsCap+2)
	for i := 0; i < EnvironmentsCap+1; i++ {
		envs = append(envs, github.Environment{Name: fmt.Sprintf("preview-%05d", i), BranchPolicy: github.BranchPolicyAny})
	}
	envs = append(envs, github.Environment{Name: "zz-production", HasRequiredReviewers: true, BranchPolicy: github.BranchPolicyProtected})
	mock.environments = map[string][]github.Environment{"test-org/repo1": envs}

	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	p, _ := c.Collect(context.Background(), componentsdk.LevelAudit)
	if !p.Environments.Truncated || p.Environments.TruncatedDropped != 2 {
		t.Fatalf("truncation = %v/%d, want true/2", p.Environments.Truncated, p.Environments.TruncatedDropped)
	}
	if len(p.Environments.PerEnvironment) != EnvironmentsCap {
		t.Fatalf("row count = %d, want %d", len(p.Environments.PerEnvironment), EnvironmentsCap)
	}
	if p.Environments.PerEnvironment[0].Name != "zz-production" {
		t.Errorf("first kept row = %q, want the reviewer-gated environment", p.Environments.PerEnvironment[0].Name)
	}
}

// collectMembersAt runs the mock at level writing the detailed artifact, and
// returns its member rows and the gaps.
func collectMembersAt(t *testing.T, level componentsdk.Level, mock *mockGitHubClient) ([]MemberRow, []componentsdk.Gap) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, Recorder: rec, CollectDetails: true}, mock)
	p, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatal(err)
	}
	if p.Members == nil {
		t.Fatal("no member inventory")
	}
	return p.Members.PerMember, rec.Gaps()
}

// detailedGapAt returns the gap at pointer in the detailed artifact, or nil.
func detailedGapAt(gaps []componentsdk.Gap, pointer string) *componentsdk.Gap {
	for i, g := range gaps {
		if g.Path == DetailedPath && g.Pointer == pointer {
			return &gaps[i]
		}
	}
	return nil
}

func TestSurfaces_MemberRowsTakeTheSAMLNameID(t *testing.T) {
	mock := richMock()
	mock.sso = &github.OrgSSO{Configured: true, LinkedMembers: 1, NameIDs: map[string]string{"alice": "alice@idp.example.com"}}
	rows, gaps := collectMembersAt(t, componentsdk.LevelAudit, mock)
	// alice, bob, then the outside collaborator carol.
	if len(rows) != 3 || rows[0].SAMLNameID != "alice@idp.example.com" || rows[1].SAMLNameID != "" || rows[2].SAMLNameID != "" {
		t.Errorf("rows = %+v, want alice's NameID alone", rows)
	}
	for _, g := range gaps {
		if strings.HasSuffix(g.Pointer, "/saml_name_id") {
			t.Errorf("unexpected gap %+v: a member with no linked SAML identity has no NameID", g)
		}
	}
}

func TestSurfaces_MemberRowsLeaveTheNameIDOutWhenTheSAMLReadFails(t *testing.T) {
	mock := richMock()
	mock.ssoErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, github.ErrPermissionDenied)
	_, gaps := collectMembersAt(t, componentsdk.LevelAudit, mock)
	for i, want := range []bool{true, true, false} {
		g := detailedGapAt(gaps, rowPointer("/members/per_member", i, "saml_name_id"))
		if (g != nil) != want || g != nil && g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("row %d: gap = %+v, want one %t, since outside collaborators have no SAML identity", i, g, want)
		}
	}

	mock = richMock()
	mock.sso = &github.OrgSSO{Configured: true, LinkedMembers: 1, NameIDs: map[string]string{"alice": "alice@idp.example.com"}, More: true}
	_, gaps = collectMembersAt(t, componentsdk.LevelAudit, mock)
	if g := detailedGapAt(gaps, rowPointer("/members/per_member", 0, "saml_name_id")); g != nil {
		t.Errorf("alice's row has gap %+v, want her NameID", g)
	}
	if g := detailedGapAt(gaps, rowPointer("/members/per_member", 1, "saml_name_id")); g == nil || g.Code != componentsdk.CodeTooLarge {
		t.Errorf("bob's row has gap %+v, want too_large, since his identity may be past the cap", g)
	}
}

// A run at the audit level that writes neither the detailed artifact nor
// the access file does not read the SAML identities.
func TestSurfaces_SAMLIdentitiesReadOnlyForTheirFiles(t *testing.T) {
	for _, tc := range []struct {
		details, access bool
		reads           int
	}{{false, false, 0}, {true, false, 1}, {false, true, 1}, {true, true, 1}} {
		mock := richMock()
		c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, CollectDetails: tc.details, CollectAccess: tc.access}, mock)
		if _, err := c.Collect(context.Background(), componentsdk.LevelAudit); err != nil {
			t.Fatal(err)
		}
		if mock.ssoReads != tc.reads {
			t.Errorf("details %t, access %t: %d SAML reads, want %d", tc.details, tc.access, mock.ssoReads, tc.reads)
		}
	}
}

// At internal, an outside collaborator's two-factor status comes from the
// list of outside collaborators without it.
func TestSurfaces_OutsideCollaboratorRowsTakeTheirTwoFactorStatus(t *testing.T) {
	mock := richMock()
	mock.membership.CollaboratorsTwoFADisabled = map[string]bool{"carol": true}
	rows, _ := collectMembersAt(t, componentsdk.LevelInternal, mock)
	if len(rows) != 3 || rows[2].Login != "carol" || rows[2].TwoFactorEnabled == nil || *rows[2].TwoFactorEnabled {
		t.Errorf("rows = %+v, want carol without two-factor authentication", rows)
	}

	mock = richMock()
	mock.membership.CollaboratorsTwoFADisabled = nil
	mock.membership.CollaboratorsTwoFAErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, github.ErrPermissionDenied)
	rows, gaps := collectMembersAt(t, componentsdk.LevelInternal, mock)
	if rows[2].TwoFactorEnabled != nil || rows[0].TwoFactorEnabled == nil {
		t.Errorf("rows = %+v, want carol's status left out and the members' kept", rows)
	}
	if g := detailedGapAt(gaps, rowPointer("/members/per_member", 2, "two_factor_enabled")); g == nil || g.Code != componentsdk.CodePermissionDenied {
		t.Errorf("carol's gap = %+v, want permission_denied", g)
	}
}
