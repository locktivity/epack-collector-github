package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool {
	return &b
}

// assertPct fails the test unless got is a non-nil percentage equal to want.
func assertPct(t *testing.T, name string, got *int, want int) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %d", name, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %d, want %d", name, *got, want)
	}
}

func TestSchemaVersion(t *testing.T) {
	// Verify the schema version constant matches expected value
	if SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", SchemaVersion, "1.0.0")
	}

	// Verify NewOrgPosture sets the schema version correctly
	posture := NewOrgPosture("test-org")
	if posture.SchemaVersion != "1.0.0" {
		t.Errorf("posture.SchemaVersion = %q, want %q", posture.SchemaVersion, "1.0.0")
	}
}

func TestOutputJSONStructure(t *testing.T) {
	// Test that JSON output has all required fields with correct types
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositories: []github.Repository{
			{
				Name:                          "repo1",
				Owner:                         struct{ Login string }{Login: "test-org"},
				HasVulnerabilityAlertsEnabled: true,
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name: "main",
					BranchProtectionRule: &github.BranchProtectionRule{
						RequiresApprovingReviews: true,
					},
				},
			},
		},
		securitySettings: map[string]*github.SecuritySettings{
			"repo1": {SecretScanning: true},
		},
	}

	c := NewWithClient(Config{
		Organization:    "test-org",
		IncludePatterns: []string{"*"},
		ExcludePatterns: []string{},
	}, mock)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	// Marshal to JSON and unmarshal to map to verify structure
	jsonBytes, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("failed to marshal posture: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// Check top-level required fields
	topLevelRequired := []string{
		"schema_version", "collected_at", "organization",
		"scope", "posture", "access_control",
		"branch_protection_rules", "security_features",
	}
	for _, field := range topLevelRequired {
		if _, ok := data[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Check scope fields
	scope, ok := data["scope"].(map[string]interface{})
	if !ok {
		t.Fatal("scope is not an object")
	}
	for _, field := range []string{"include_patterns", "exclude_patterns", "repositories_coverage"} {
		if _, ok := scope[field]; !ok {
			t.Errorf("scope missing required field: %s", field)
		}
	}
	// Verify patterns are arrays, not null
	if scope["include_patterns"] == nil {
		t.Error("include_patterns should be an array, not null")
	}
	if scope["exclude_patterns"] == nil {
		t.Error("exclude_patterns should be an array, not null")
	}

	// Check posture fields
	postureData, ok := data["posture"].(map[string]interface{})
	if !ok {
		t.Fatal("posture is not an object")
	}
	for _, field := range []string{"branch_protection_coverage", "security_features_coverage"} {
		if _, ok := postureData[field]; !ok {
			t.Errorf("posture missing required field: %s", field)
		}
	}

	// Check access_control fields
	accessControl, ok := data["access_control"].(map[string]interface{})
	if !ok {
		t.Fatal("access_control is not an object")
	}
	if _, ok := accessControl["two_factor_required"]; !ok {
		t.Error("access_control missing required field: two_factor_required")
	}

	// Check branch_protection_rules fields
	bpRules, ok := data["branch_protection_rules"].(map[string]interface{})
	if !ok {
		t.Fatal("branch_protection_rules is not an object")
	}
	bpFields := []string{
		"pull_request_required", "approving_reviews", "dismiss_stale_reviews",
		"code_owner_reviews", "status_checks", "signed_commits", "admin_enforcement",
	}
	for _, field := range bpFields {
		if _, ok := bpRules[field]; !ok {
			t.Errorf("branch_protection_rules missing required field: %s", field)
		}
	}

	// Check security_features fields
	secFeatures, ok := data["security_features"].(map[string]interface{})
	if !ok {
		t.Fatal("security_features is not an object")
	}
	secFields := []string{
		"vulnerability_alerts", "code_scanning", "secret_scanning",
		"secret_scanning_push_protection", "dependabot_security_updates",
	}
	for _, field := range secFields {
		if _, ok := secFeatures[field]; !ok {
			t.Errorf("security_features missing required field: %s", field)
		}
	}
}

func TestPercent(t *testing.T) {
	tests := []struct {
		name  string
		count int
		total int
		want  int
	}{
		{"zero total returns zero", 5, 0, 0},
		{"zero count returns zero", 0, 100, 0},
		{"50 percent", 50, 100, 50},
		{"100 percent", 100, 100, 100},
		{"33 percent truncates", 1, 3, 33},
		{"66 percent truncates", 2, 3, 66},
		{"small numbers", 1, 10, 10},
		{"all enabled", 45, 45, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := percent(tt.count, tt.total)
			if got != tt.want {
				t.Errorf("percent(%d, %d) = %d, want %d", tt.count, tt.total, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	config := Config{
		Organization:    "test-org",
		GitHubToken:     "test-token",
		IncludePatterns: []string{"*"},
		ExcludePatterns: []string{"*-archive"},
	}

	collector, err := New(config)

	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if collector.config.Organization != "test-org" {
		t.Errorf("config.Organization = %q, want %q", collector.config.Organization, "test-org")
	}
	if collector.config.GitHubToken != "test-token" {
		t.Errorf("config.GitHubToken = %q, want %q", collector.config.GitHubToken, "test-token")
	}
	if collector.client == nil {
		t.Error("client is nil")
	}
}

func TestNew_AuthErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "missing all auth",
			config: Config{
				Organization: "test-org",
				GitHubToken:  "",
			},
			wantErr: "authentication required: provide app_id + private_key (recommended) or github_token",
		},
		{
			name: "app auth missing installation_id",
			config: Config{
				Organization:   "test-org",
				AppID:          12345,
				PrivateKey:     "fake-key",
				InstallationID: 0,
			},
			wantErr: "installation_id is required when using GitHub App authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.config)

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCollect_ValidationErrors(t *testing.T) {
	// Test Collect() validation (organization check)
	mock := &mockGitHubClient{}
	config := Config{
		Organization: "",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	_, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "organization is required" {
		t.Errorf("error = %q, want %q", err.Error(), "organization is required")
	}
}

// mockGitHubClient implements github.GitHubClient for testing.
type mockGitHubClient struct {
	orgSecurity      *github.OrgSecurity
	orgSecurityErr   error
	repositories     []github.Repository
	repositoriesErr  error
	securitySettings map[string]*github.SecuritySettings // key: "owner/repo"
	requestedRepos   []string

	// Audit / internal surface fixtures.
	orgSettings    *github.OrgSettings
	orgSettingsErr error

	secretAlerts     map[string][]github.SecretScanningAlert
	codeAlerts       map[string][]github.CodeScanningAlert
	dependabotAlerts map[string][]github.DependabotAlert
	alertListErr     error
	alertListMore    bool // every alert list reached the fetch cap

	membership        *github.OrgMembership
	membershipErr     error
	codeowners        map[string]codeownersFixture // key: "owner/repo"
	codeownersErr     error
	orgHooks          []github.Hook
	repoHooks         map[string][]github.Hook
	hooksErr          error
	deployKeys        map[string][]github.DeployKey
	deployKeysErr     error
	orgRunners        []github.Runner
	orgRunnerTotal    int // reported total override; default len(orgRunners)
	repoRunners       map[string][]github.Runner
	actionsErr        error
	secretNames       []string
	environments      map[string][]github.Environment // key: "owner/repo"
	environmentTotals map[string]int                  // reported total override; default len(fixture)
	environmentsErr   error
	envPatterns       map[string][]github.BranchPolicyPattern // key: "owner/repo#env"
	envApps           map[string][]string                     // key: "owner/repo#env"
	envSubErr         error
	auditEvents       []github.AuditEvent
	auditMore         bool
	auditErr          error
	installations     []github.Installation
	installationTotal int // reported total override; default len(installations)
	installationErr   error
	pats              []github.PATGrant
	patsErr           error

	branchRules     map[string][]github.BranchRule // key: "owner/repo"
	branchRulesErr  map[string]error               // key: "owner/repo"
	rulesets        map[int64]*github.Ruleset
	rulesetErr      error
	rulesetRequests []int64
}

type codeownersFixture struct {
	present bool
	path    string
	hash    string
}

func (m *mockGitHubClient) FetchOrgSecurity(ctx context.Context, org string) (*github.OrgSecurity, error) {
	if m.orgSecurityErr != nil {
		return nil, m.orgSecurityErr
	}
	if m.orgSecurity == nil {
		return &github.OrgSecurity{}, nil
	}
	return m.orgSecurity, nil
}

func (m *mockGitHubClient) FetchRepositories(ctx context.Context, org string, callback func([]github.Repository) error) error {
	if m.repositoriesErr != nil {
		return m.repositoriesErr
	}
	return callback(m.repositories)
}

func (m *mockGitHubClient) FetchSecuritySettings(ctx context.Context, owner, repo string) (*github.SecuritySettings, error) {
	key := owner + "/" + repo
	m.requestedRepos = append(m.requestedRepos, key)
	if settings, ok := m.securitySettings[key]; ok {
		return settings, nil
	}
	return &github.SecuritySettings{}, nil
}

func (m *mockGitHubClient) GetBranchRules(ctx context.Context, owner, repo, branch string) ([]github.BranchRule, error) {
	key := owner + "/" + repo
	if err := m.branchRulesErr[key]; err != nil {
		return nil, err
	}
	return m.branchRules[key], nil
}

func (m *mockGitHubClient) GetRepoRuleset(ctx context.Context, owner, repo string, rulesetID int64) (*github.Ruleset, error) {
	m.rulesetRequests = append(m.rulesetRequests, rulesetID)
	if m.rulesetErr != nil {
		return nil, m.rulesetErr
	}
	if rs, ok := m.rulesets[rulesetID]; ok {
		return rs, nil
	}
	return nil, fmt.Errorf("%w: ruleset %d", github.ErrNotFound, rulesetID)
}

func (m *mockGitHubClient) GetOrgSettings(ctx context.Context, org string) (*github.OrgSettings, error) {
	if m.orgSettingsErr != nil {
		return nil, m.orgSettingsErr
	}
	if m.orgSettings != nil {
		return m.orgSettings, nil
	}
	return &github.OrgSettings{}, nil
}

func (m *mockGitHubClient) ListSecretScanningAlerts(ctx context.Context, owner, repo string) ([]github.SecretScanningAlert, bool, error) {
	if m.alertListErr != nil {
		return nil, false, m.alertListErr
	}
	return m.secretAlerts[owner+"/"+repo], m.alertListMore, nil
}

func (m *mockGitHubClient) ListCodeScanningAlerts(ctx context.Context, owner, repo string) ([]github.CodeScanningAlert, bool, error) {
	if m.alertListErr != nil {
		return nil, false, m.alertListErr
	}
	return m.codeAlerts[owner+"/"+repo], m.alertListMore, nil
}

func (m *mockGitHubClient) ListDependabotAlerts(ctx context.Context, owner, repo string) ([]github.DependabotAlert, bool, error) {
	if m.alertListErr != nil {
		return nil, false, m.alertListErr
	}
	return m.dependabotAlerts[owner+"/"+repo], m.alertListMore, nil
}

func (m *mockGitHubClient) GetOrgMembership(ctx context.Context, org string) (*github.OrgMembership, error) {
	if m.membershipErr != nil {
		return nil, m.membershipErr
	}
	if m.membership != nil {
		return m.membership, nil
	}
	return &github.OrgMembership{}, nil
}

func (m *mockGitHubClient) GetCodeownersInfo(ctx context.Context, owner, repo string, wantHash bool) (bool, string, string, error) {
	if m.codeownersErr != nil {
		return false, "", "", m.codeownersErr
	}
	f := m.codeowners[owner+"/"+repo]
	if !wantHash {
		return f.present, f.path, "", nil
	}
	return f.present, f.path, f.hash, nil
}

func (m *mockGitHubClient) ListOrgHooks(ctx context.Context, org string) ([]github.Hook, error) {
	if m.hooksErr != nil {
		return nil, m.hooksErr
	}
	return m.orgHooks, nil
}

func (m *mockGitHubClient) ListRepoHooks(ctx context.Context, owner, repo string) ([]github.Hook, error) {
	if m.hooksErr != nil {
		return nil, m.hooksErr
	}
	return m.repoHooks[owner+"/"+repo], nil
}

func (m *mockGitHubClient) ListRepoDeployKeys(ctx context.Context, owner, repo string) ([]github.DeployKey, error) {
	if m.deployKeysErr != nil {
		return nil, m.deployKeysErr
	}
	return m.deployKeys[owner+"/"+repo], nil
}

func (m *mockGitHubClient) ListOrgRunners(ctx context.Context, org string) ([]github.Runner, int, error) {
	if m.actionsErr != nil {
		return nil, 0, m.actionsErr
	}
	return m.orgRunners, max(m.orgRunnerTotal, len(m.orgRunners)), nil
}

func (m *mockGitHubClient) ListRepoRunners(ctx context.Context, owner, repo string) ([]github.Runner, int, error) {
	if m.actionsErr != nil {
		return nil, 0, m.actionsErr
	}
	runners := m.repoRunners[owner+"/"+repo]
	return runners, len(runners), nil
}

func (m *mockGitHubClient) ListOrgActionsSecretNames(ctx context.Context, org string) ([]string, int, error) {
	if m.actionsErr != nil {
		return nil, 0, m.actionsErr
	}
	return m.secretNames, len(m.secretNames), nil
}

func (m *mockGitHubClient) ListRepoEnvironments(ctx context.Context, owner, repo string) ([]github.Environment, int, error) {
	if m.environmentsErr != nil {
		return nil, 0, m.environmentsErr
	}
	envs := m.environments[owner+"/"+repo]
	total := len(envs)
	if t, ok := m.environmentTotals[owner+"/"+repo]; ok {
		total = t
	}
	return envs, total, nil
}

func (m *mockGitHubClient) ListEnvironmentBranchPolicies(ctx context.Context, owner, repo, environment string) ([]github.BranchPolicyPattern, error) {
	if m.envSubErr != nil {
		return nil, m.envSubErr
	}
	return m.envPatterns[owner+"/"+repo+"#"+environment], nil
}

func (m *mockGitHubClient) ListEnvironmentProtectionApps(ctx context.Context, owner, repo, environment string) ([]string, error) {
	if m.envSubErr != nil {
		return nil, m.envSubErr
	}
	return m.envApps[owner+"/"+repo+"#"+environment], nil
}

func (m *mockGitHubClient) GetOrgAuditLog(ctx context.Context, org, sinceISO string, maxEvents int) ([]github.AuditEvent, bool, error) {
	if m.auditErr != nil {
		return nil, false, m.auditErr
	}
	return m.auditEvents, m.auditMore, nil
}

func (m *mockGitHubClient) ListOrgInstallations(ctx context.Context, org string) ([]github.Installation, int, error) {
	if m.installationErr != nil {
		return nil, 0, m.installationErr
	}
	return m.installations, max(m.installationTotal, len(m.installations)), nil
}

func (m *mockGitHubClient) ListOrgPATs(ctx context.Context, org string) ([]github.PATGrant, bool, error) {
	if m.patsErr != nil {
		return nil, false, m.patsErr
	}
	return m.pats, false, nil
}

func TestCollect_EmptyOrganization(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositories: []github.Repository{},
	}

	config := Config{
		Organization: "test-org",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No repos, so coverage has no population and is null.
	if posture.Scope.RepositoriesCoverage != nil {
		t.Errorf("RepositoriesCoverage = %d, want null", *posture.Scope.RepositoriesCoverage)
	}
	assertPct(t, "IncludedRepositoryCount", posture.Scope.IncludedRepositoryCount, 0)
	if posture.Posture.SecurityFeaturesCoverage != nil || posture.SecurityFeatures.CodeScanning != nil {
		t.Errorf("security feature metrics over no repositories should be null, got %+v", posture.SecurityFeatures)
	}
	if posture.AccessControl.TwoFactorRequired == nil || *posture.AccessControl.TwoFactorRequired != true {
		t.Errorf("TwoFactorRequired = %v, want true", posture.AccessControl.TwoFactorRequired)
	}
}

func TestCollect_FullOrganization(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositories: []github.Repository{
			{
				Name:  "repo1",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name: "main",
					BranchProtectionRule: &github.BranchProtectionRule{
						RequiresApprovingReviews:     true,
						RequiredApprovingReviewCount: 1,
						DismissesStaleReviews:        true,
						RequiresCodeOwnerReviews:     true,
						RequiresStatusChecks:         true,
						RequiresCommitSignatures:     true,
						IsAdminEnforced:              true,
					},
				},
				HasVulnerabilityAlertsEnabled: true,
			},
			{
				Name:  "repo2",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name: "main",
					BranchProtectionRule: &github.BranchProtectionRule{
						RequiresApprovingReviews:     true,
						RequiredApprovingReviewCount: 2,
						RequiresStatusChecks:         true,
					},
				},
				HasVulnerabilityAlertsEnabled: true,
			},
			{
				Name:  "repo3",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: nil, // No branch protection
				},
				HasVulnerabilityAlertsEnabled: false,
			},
		},
		securitySettings: map[string]*github.SecuritySettings{
			"test-org/repo1": {
				SecretScanning:               true,
				SecretScanningPushProtection: true,
				DependabotSecurityUpdates:    true,
				CodeScanningEnabled:          true,
			},
			"test-org/repo2": {
				SecretScanning:               true,
				SecretScanningPushProtection: false,
				DependabotSecurityUpdates:    true,
				CodeScanningEnabled:          false,
			},
			"test-org/repo3": {
				SecretScanning:               false,
				SecretScanningPushProtection: false,
				DependabotSecurityUpdates:    false,
				CodeScanningEnabled:          false,
			},
		},
	}

	config := Config{
		Organization: "test-org",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 3 repos included, no exclusions = 100% coverage
	assertPct(t, "RepositoriesCoverage", posture.Scope.RepositoriesCoverage, 100)

	// Check access control
	if posture.AccessControl.TwoFactorRequired == nil || *posture.AccessControl.TwoFactorRequired != true {
		t.Errorf("TwoFactorRequired = %v, want true", posture.AccessControl.TwoFactorRequired)
	}

	// Check branch protection (2/3 repos have it = 66%)
	assertPct(t, "BranchProtectionCoverage", posture.Posture.BranchProtectionCoverage, 66)

	// Check individual branch protection rules
	assertPct(t, "ApprovingReviews", posture.BranchProtectionRules.ApprovingReviews, 66)       // 2/3
	assertPct(t, "DismissStaleReviews", posture.BranchProtectionRules.DismissStaleReviews, 33) // 1/3
	assertPct(t, "StatusChecks", posture.BranchProtectionRules.StatusChecks, 66)               // 2/3
	assertPct(t, "AdminEnforcement", posture.BranchProtectionRules.AdminEnforcement, 33)       // 1/3
	assertPct(t, "ForcePushesBlocked", posture.BranchProtectionRules.ForcePushesBlocked, 66)   // 2/3

	// Check security features
	assertPct(t, "VulnerabilityAlerts", posture.SecurityFeatures.VulnerabilityAlerts, 66) // 2/3
	assertPct(t, "SecretScanning", posture.SecurityFeatures.SecretScanning, 66)           // 2/3
	assertPct(t, "CodeScanning", posture.SecurityFeatures.CodeScanning, 33)               // 1/3
}

func TestCollect_WithFilters(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositories: []github.Repository{
			{
				Name:  "prod-app",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: &github.BranchProtectionRule{RequiresApprovingReviews: true},
				},
				HasVulnerabilityAlertsEnabled: true,
			},
			{
				Name:  "test-app",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: nil,
				},
				HasVulnerabilityAlertsEnabled: false,
			},
			{
				Name:  "prod-api",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: &github.BranchProtectionRule{RequiresApprovingReviews: true},
				},
				HasVulnerabilityAlertsEnabled: true,
			},
		},
		securitySettings: map[string]*github.SecuritySettings{},
	}

	config := Config{
		Organization:    "test-org",
		GitHubToken:     "test-token",
		IncludePatterns: []string{"prod-*"},
		ExcludePatterns: []string{},
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only prod-* repos should be counted (2 of 3 repos = 66% coverage)
	assertPct(t, "RepositoriesCoverage", posture.Scope.RepositoriesCoverage, 66)

	// Both prod repos have branch protection = 100%
	assertPct(t, "BranchProtectionCoverage", posture.Posture.BranchProtectionCoverage, 100)
}

func TestCollect_ExcludePatterns(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositories: []github.Repository{
			{
				Name:  "app",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: &github.BranchProtectionRule{RequiresApprovingReviews: true},
				},
			},
			{
				Name:  "app-archive",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: nil,
				},
			},
			{
				Name:  "test-utils",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: nil,
				},
			},
		},
		securitySettings: map[string]*github.SecuritySettings{},
	}

	config := Config{
		Organization:    "test-org",
		GitHubToken:     "test-token",
		IncludePatterns: []string{"*"},
		ExcludePatterns: []string{"*-archive", "test-*"},
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only "app" should be counted (1 of 3 repos = 33% coverage)
	assertPct(t, "RepositoriesCoverage", posture.Scope.RepositoriesCoverage, 33)
}

func TestCollect_SkipsArchivedRepositories(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositories: []github.Repository{
			{
				Name:       "active-app",
				Owner:      struct{ Login string }{Login: "test-org"},
				IsArchived: false,
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: &github.BranchProtectionRule{RequiresApprovingReviews: true},
				},
				HasVulnerabilityAlertsEnabled: true,
			},
			{
				Name:       "archived-app",
				Owner:      struct{ Login string }{Login: "test-org"},
				IsArchived: true,
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: nil,
				},
				HasVulnerabilityAlertsEnabled: false,
			},
		},
		securitySettings: map[string]*github.SecuritySettings{
			"test-org/active-app": {
				SecretScanning:               true,
				SecretScanningPushProtection: true,
				DependabotSecurityUpdates:    true,
				CodeScanningEnabled:          true,
			},
			"test-org/archived-app": {
				CodeScanningPermissionDenied: true,
				CodeScanningErrorMessage:     "Advanced Security must be enabled for this repository to use code scanning.",
			},
		},
	}

	config := Config{
		Organization:    "test-org",
		GitHubToken:     "test-token",
		IncludePatterns: []string{"*"},
		ExcludePatterns: []string{},
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertPct(t, "RepositoriesCoverage", posture.Scope.RepositoriesCoverage, 50)
	assertPct(t, "BranchProtectionCoverage", posture.Posture.BranchProtectionCoverage, 100)
	assertPct(t, "CodeScanning", posture.SecurityFeatures.CodeScanning, 100)
	if posture.Diagnostics != nil {
		t.Errorf("Diagnostics = %+v, want nil", posture.Diagnostics)
	}
	if len(mock.requestedRepos) != 1 || mock.requestedRepos[0] != "test-org/active-app" {
		t.Errorf("requestedRepos = %v, want [test-org/active-app]", mock.requestedRepos)
	}
}

func TestCollect_OrgSecurityError(t *testing.T) {
	// The organization read is the sign-in, so its failure fails the run with
	// the failure's code instead of emitting zeros.
	mock := &mockGitHubClient{
		orgSecurityErr: &github.APIError{StatusCode: 401, Path: "/orgs/test-org", Message: "Bad credentials"},
	}

	config := Config{
		Organization: "test-org",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	_, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if got := componentsdk.Classify(err); got != componentsdk.CodeAuthFailed {
		t.Fatalf("Collect() error = %v (code %s), want auth_failed", err, got)
	}
	if mock.requestedRepos != nil {
		t.Errorf("requested repos %v after a failed sign-in", mock.requestedRepos)
	}
}

func TestCollect_RepositoriesError(t *testing.T) {
	// A non-permission error on the repo list degrades to a warning rather than
	// aborting the run.
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositoriesErr: errors.New("network timeout"),
	}

	config := Config{
		Organization: "test-org",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("expected degraded success, got error: %v", err)
	}
	if posture.Diagnostics == nil || !anyContains(posture.Diagnostics.Warnings, "repositories") {
		t.Errorf("expected a repositories warning, got %+v", posture.Diagnostics)
	}
	if posture.Scope.RepositoriesCoverage != nil || posture.Scope.IncludedRepositoryCount != nil ||
		posture.Posture.SecurityFeaturesCoverage != nil || posture.SecurityFeatures.VulnerabilityAlerts != nil {
		t.Errorf("repository metrics should be null when the list failed, got scope %+v, features %+v", posture.Scope, posture.SecurityFeatures)
	}
}

func TestCollect_CoreSurfacePermissionDenied(t *testing.T) {
	// A refused sign-in fails the run as permission_denied.
	mock := &mockGitHubClient{
		orgSecurityErr: fmt.Errorf("%w: /orgs/test-org (status 403)", github.ErrPermissionDenied),
	}

	config := Config{
		Organization: "test-org",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	_, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if !errors.Is(err, github.ErrPermissionDenied) {
		t.Fatalf("Collect() error = %v, want the permission denial", err)
	}
}

func TestCollect_DefaultIncludePatterns(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: boolPtr(true),
		},
		repositories: []github.Repository{
			{
				Name:  "any-repo",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{},
			},
		},
		securitySettings: map[string]*github.SecuritySettings{},
	}

	config := Config{
		Organization:    "test-org",
		GitHubToken:     "test-token",
		IncludePatterns: nil, // No patterns - should default to ["*"]
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should include all repos when no patterns specified (100% coverage)
	assertPct(t, "RepositoriesCoverage", posture.Scope.RepositoriesCoverage, 100)

	// Scope should show default pattern
	if len(posture.Scope.IncludePatterns) != 1 || posture.Scope.IncludePatterns[0] != "*" {
		t.Errorf("IncludePatterns = %v, want [*]", posture.Scope.IncludePatterns)
	}
}

func TestCollect_SecurityFeaturesCoverage(t *testing.T) {
	// Test that security features coverage is calculated correctly as average of 5 features
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{},
		repositories: []github.Repository{
			{
				Name:                          "repo1",
				Owner:                         struct{ Login string }{Login: "org"},
				HasVulnerabilityAlertsEnabled: true,
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{},
			},
			{
				Name:                          "repo2",
				Owner:                         struct{ Login string }{Login: "org"},
				HasVulnerabilityAlertsEnabled: true,
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{},
			},
		},
		securitySettings: map[string]*github.SecuritySettings{
			"org/repo1": {
				SecretScanning:               true,
				SecretScanningPushProtection: true,
				DependabotSecurityUpdates:    true,
				CodeScanningEnabled:          true,
			},
			"org/repo2": {
				SecretScanning:               true,
				SecretScanningPushProtection: true,
				DependabotSecurityUpdates:    true,
				CodeScanningEnabled:          true,
			},
		},
	}

	config := Config{
		Organization: "org",
		GitHubToken:  "token",
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 5 features enabled on all 2 repos = 100% coverage
	// (2+2+2+2+2) / (2*5) = 10/10 = 100%
	assertPct(t, "SecurityFeaturesCoverage", posture.Posture.SecurityFeaturesCoverage, 100)
}

func TestCollect_InsufficientPermissions(t *testing.T) {
	// Test that when org security returns nil values (insufficient permissions),
	// the collector still works and reports nil for access control
	mock := &mockGitHubClient{
		orgSecurity: &github.OrgSecurity{
			TwoFactorRequired: nil, // Unknown - insufficient permissions
		},
		repositories: []github.Repository{
			{
				Name:  "repo1",
				Owner: struct{ Login string }{Login: "test-org"},
				DefaultBranchRef: struct {
					Name                 string
					BranchProtectionRule *github.BranchProtectionRule
				}{
					Name:                 "main",
					BranchProtectionRule: &github.BranchProtectionRule{RequiresApprovingReviews: true},
				},
				HasVulnerabilityAlertsEnabled: true,
			},
		},
		securitySettings: map[string]*github.SecuritySettings{},
	}

	config := Config{
		Organization: "test-org",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	posture, err := collector.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Access control should be nil (unknown) when permissions are insufficient
	if posture.AccessControl.TwoFactorRequired != nil {
		t.Errorf("TwoFactorRequired = %v, want nil (unknown)", posture.AccessControl.TwoFactorRequired)
	}

	// Repository metrics should still work
	assertPct(t, "RepositoriesCoverage", posture.Scope.RepositoriesCoverage, 100)
	assertPct(t, "BranchProtectionCoverage", posture.Posture.BranchProtectionCoverage, 100)
}

func TestToVCSPosture(t *testing.T) {
	// Test transformation from OrgPosture to normalized VCSPosture
	orgPosture := &OrgPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   "2024-01-15T10:00:00Z",
		Organization:  "test-org",
		Scope: Scope{
			IncludePatterns:      []string{"*"},
			ExcludePatterns:      []string{},
			RepositoriesCoverage: ptr(80),
		},
		Posture: Posture{
			BranchProtectionCoverage: ptr(75),
			SecurityFeaturesCoverage: ptr(60),
		},
		AccessControl: AccessControl{
			TwoFactorRequired: boolPtr(true),
		},
		BranchProtectionRules: BranchProtectionRules{
			PullRequestRequired: ptr(90),
			ApprovingReviews:    ptr(85),
			DismissStaleReviews: ptr(40),
			CodeOwnerReviews:    ptr(30),
			StatusChecks:        ptr(70),
			SignedCommits:       ptr(20),
			AdminEnforcement:    ptr(50),
		},
		SecurityFeatures: SecurityFeatures{
			VulnerabilityAlerts:          ptr(95),
			CodeScanning:                 ptr(45),
			SecretScanning:               ptr(80),
			SecretScanningPushProtection: ptr(60),
			DependabotSecurityUpdates:    ptr(70),
		},
	}

	vcsPosture := orgPosture.ToVCSPosture()

	// Verify basic fields
	if vcsPosture.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", vcsPosture.SchemaVersion, "1.0.0")
	}
	if vcsPosture.Provider != "github" {
		t.Errorf("Provider = %q, want %q", vcsPosture.Provider, "github")
	}
	if vcsPosture.Organization != "test-org" {
		t.Errorf("Organization = %q, want %q", vcsPosture.Organization, "test-org")
	}

	// Verify coverage mapping
	if vcsPosture.RepoCoveragePct == nil || *vcsPosture.RepoCoveragePct != 80 {
		t.Errorf("RepoCoveragePct = %v, want 80", vcsPosture.RepoCoveragePct)
	}

	// Verify org security
	if vcsPosture.OrgSecurity.TwoFactorRequired == nil || !*vcsPosture.OrgSecurity.TwoFactorRequired {
		t.Error("OrgSecurity.TwoFactorRequired is not true")
	}

	// Verify branch protection mappings
	bp := vcsPosture.BranchProtection
	for name, got := range map[string]struct {
		value *float64
		want  float64
	}{
		"PRRequiredPct":       {bp.PRRequiredPct, 90},
		"ApprovingReviewsPct": {bp.ApprovingReviewsPct, 85},
		"StatusChecksPct":     {bp.StatusChecksPct, 70},
		"SignedCommitsPct":    {bp.SignedCommitsPct, 20},
	} {
		if got.value == nil || *got.value != got.want {
			t.Errorf("BranchProtection.%s = %v, want %v", name, got.value, got.want)
		}
	}

	// Verify security features mappings
	sf := vcsPosture.SecurityFeatures
	for name, got := range map[string]struct {
		value *float64
		want  float64
	}{
		"VulnAlertsPct":     {sf.VulnAlertsPct, 95},
		"SecretScanningPct": {sf.SecretScanningPct, 80},
		"CodeScanningPct":   {sf.CodeScanningPct, 45},
	} {
		if got.value == nil || *got.value != got.want {
			t.Errorf("SecurityFeatures.%s = %v, want %v", name, got.value, got.want)
		}
	}
}

func TestToVCSPosture_NilTwoFactor(t *testing.T) {
	// An unknown 2FA requirement (insufficient permissions) stays unknown
	// rather than reading as not required.
	orgPosture := &OrgPosture{
		Organization: "test-org",
		AccessControl: AccessControl{
			TwoFactorRequired: nil,
		},
	}

	vcsPosture := orgPosture.ToVCSPosture()

	if vcsPosture.OrgSecurity.TwoFactorRequired != nil {
		t.Errorf("OrgSecurity.TwoFactorRequired = %v, want unknown", *vcsPosture.OrgSecurity.TwoFactorRequired)
	}
}

func TestToVCSPosture_FalseTwoFactor(t *testing.T) {
	// Test that explicit false TwoFactorRequired maps to false
	orgPosture := &OrgPosture{
		Organization: "test-org",
		AccessControl: AccessControl{
			TwoFactorRequired: boolPtr(false),
		},
	}

	vcsPosture := orgPosture.ToVCSPosture()

	if vcsPosture.OrgSecurity.TwoFactorRequired == nil || *vcsPosture.OrgSecurity.TwoFactorRequired {
		t.Errorf("OrgSecurity.TwoFactorRequired = %v, want false", vcsPosture.OrgSecurity.TwoFactorRequired)
	}
}

func TestVCSPostureJSONStructure(t *testing.T) {
	// Test that VCSPosture JSON output matches vcs-posture@v1 schema
	orgPosture := &OrgPosture{
		Organization: "test-org",
		Scope: Scope{
			RepositoriesCoverage: ptr(100),
		},
		AccessControl: AccessControl{
			TwoFactorRequired: boolPtr(true),
		},
		BranchProtectionRules: BranchProtectionRules{
			PullRequestRequired: ptr(80),
			ApprovingReviews:    ptr(75),
			StatusChecks:        ptr(60),
			SignedCommits:       ptr(10),
		},
		SecurityFeatures: SecurityFeatures{
			VulnerabilityAlerts: ptr(90),
			SecretScanning:      ptr(85),
			CodeScanning:        ptr(50),
		},
	}

	vcsPosture := orgPosture.ToVCSPosture()

	// Marshal to JSON and unmarshal to map to verify structure
	jsonBytes, err := json.Marshal(vcsPosture)
	if err != nil {
		t.Fatalf("failed to marshal VCSPosture: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// Check top-level required fields per vcs-posture@v1 schema
	topLevelRequired := []string{
		"schema_version", "collected_at", "provider", "organization",
		"org_security", "repo_coverage_pct", "branch_protection", "security_features",
	}
	for _, field := range topLevelRequired {
		if _, ok := data[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Check org_security fields
	orgSecurity, ok := data["org_security"].(map[string]interface{})
	if !ok {
		t.Fatal("org_security is not an object")
	}
	if _, ok := orgSecurity["two_factor_required"]; !ok {
		t.Error("org_security missing required field: two_factor_required")
	}

	// Check branch_protection fields
	branchProtection, ok := data["branch_protection"].(map[string]interface{})
	if !ok {
		t.Fatal("branch_protection is not an object")
	}
	bpFields := []string{
		"pr_required_pct", "approving_reviews_pct", "status_checks_pct", "signed_commits_pct",
	}
	for _, field := range bpFields {
		if _, ok := branchProtection[field]; !ok {
			t.Errorf("branch_protection missing required field: %s", field)
		}
	}

	// Check security_features fields
	securityFeatures, ok := data["security_features"].(map[string]interface{})
	if !ok {
		t.Fatal("security_features is not an object")
	}
	sfFields := []string{
		"vuln_alerts_pct", "secret_scanning_pct", "code_scanning_pct",
	}
	for _, field := range sfFields {
		if _, ok := securityFeatures[field]; !ok {
			t.Errorf("security_features missing required field: %s", field)
		}
	}
}
