package collector

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool {
	return &b
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

	c := &Collector{
		config: Config{
			Organization:    "test-org",
			IncludePatterns: []string{"*"},
			ExcludePatterns: []string{},
		},
		client: mock,
	}

	posture, err := c.Collect(context.Background())
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
	if collector == nil {
		t.Fatal("New() returned nil")
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
	_, err := collector.Collect(context.Background())

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
}

func (m *mockGitHubClient) FetchOrgSecurity(ctx context.Context, org string) (*github.OrgSecurity, error) {
	if m.orgSecurityErr != nil {
		return nil, m.orgSecurityErr
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
	if settings, ok := m.securitySettings[key]; ok {
		return settings, nil
	}
	return &github.SecuritySettings{}, nil
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
	posture, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No repos, so coverage is 0 (0/0 = 0)
	if posture.Scope.RepositoriesCoverage != 0 {
		t.Errorf("RepositoriesCoverage = %d, want 0", posture.Scope.RepositoriesCoverage)
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
						RequiresApprovingReviews: true,
						DismissesStaleReviews:    true,
						RequiresCodeOwnerReviews: true,
						RequiresStatusChecks:     true,
						RequiresCommitSignatures: true,
						IsAdminEnforced:          true,
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
						RequiresApprovingReviews: true,
						RequiresStatusChecks:     true,
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
	posture, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 3 repos included, no exclusions = 100% coverage
	if posture.Scope.RepositoriesCoverage != 100 {
		t.Errorf("RepositoriesCoverage = %d, want 100", posture.Scope.RepositoriesCoverage)
	}

	// Check access control
	if posture.AccessControl.TwoFactorRequired == nil || *posture.AccessControl.TwoFactorRequired != true {
		t.Errorf("TwoFactorRequired = %v, want true", posture.AccessControl.TwoFactorRequired)
	}

	// Check branch protection (2/3 repos have it = 66%)
	if posture.Posture.BranchProtectionCoverage != 66 {
		t.Errorf("BranchProtectionCoverage = %d, want 66", posture.Posture.BranchProtectionCoverage)
	}

	// Check individual branch protection rules
	if posture.BranchProtectionRules.ApprovingReviews != 66 { // 2/3
		t.Errorf("ApprovingReviews = %d, want 66", posture.BranchProtectionRules.ApprovingReviews)
	}
	if posture.BranchProtectionRules.DismissStaleReviews != 33 { // 1/3
		t.Errorf("DismissStaleReviews = %d, want 33", posture.BranchProtectionRules.DismissStaleReviews)
	}
	if posture.BranchProtectionRules.StatusChecks != 66 { // 2/3
		t.Errorf("StatusChecks = %d, want 66", posture.BranchProtectionRules.StatusChecks)
	}

	// Check security features
	if posture.SecurityFeatures.VulnerabilityAlerts != 66 { // 2/3
		t.Errorf("VulnerabilityAlerts = %d, want 66", posture.SecurityFeatures.VulnerabilityAlerts)
	}
	if posture.SecurityFeatures.SecretScanning != 66 { // 2/3
		t.Errorf("SecretScanning = %d, want 66", posture.SecurityFeatures.SecretScanning)
	}
	if posture.SecurityFeatures.CodeScanning != 33 { // 1/3
		t.Errorf("CodeScanning = %d, want 33", posture.SecurityFeatures.CodeScanning)
	}
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
	posture, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only prod-* repos should be counted (2 of 3 repos = 66% coverage)
	if posture.Scope.RepositoriesCoverage != 66 {
		t.Errorf("RepositoriesCoverage = %d, want 66", posture.Scope.RepositoriesCoverage)
	}

	// Both prod repos have branch protection = 100%
	if posture.Posture.BranchProtectionCoverage != 100 {
		t.Errorf("BranchProtectionCoverage = %d, want 100", posture.Posture.BranchProtectionCoverage)
	}
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
	posture, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only "app" should be counted (1 of 3 repos = 33% coverage)
	if posture.Scope.RepositoriesCoverage != 33 {
		t.Errorf("RepositoriesCoverage = %d, want 33", posture.Scope.RepositoriesCoverage)
	}
}

func TestCollect_OrgSecurityError(t *testing.T) {
	mock := &mockGitHubClient{
		orgSecurityErr: errors.New("API rate limit exceeded"),
	}

	config := Config{
		Organization: "test-org",
		GitHubToken:  "test-token",
	}

	collector := NewWithClient(config, mock)
	_, err := collector.Collect(context.Background())

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "failed to fetch org security: API rate limit exceeded" {
		t.Errorf("error = %q, want %q", err.Error(), "failed to fetch org security: API rate limit exceeded")
	}
}

func TestCollect_RepositoriesError(t *testing.T) {
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
	_, err := collector.Collect(context.Background())

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "failed to fetch repositories: network timeout" {
		t.Errorf("error = %q, want %q", err.Error(), "failed to fetch repositories: network timeout")
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
	posture, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should include all repos when no patterns specified (100% coverage)
	if posture.Scope.RepositoriesCoverage != 100 {
		t.Errorf("RepositoriesCoverage = %d, want 100", posture.Scope.RepositoriesCoverage)
	}

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
	posture, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 5 features enabled on all 2 repos = 100% coverage
	// (2+2+2+2+2) / (2*5) = 10/10 = 100%
	if posture.Posture.SecurityFeaturesCoverage != 100 {
		t.Errorf("SecurityFeaturesCoverage = %d, want 100", posture.Posture.SecurityFeaturesCoverage)
	}
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
	posture, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Access control should be nil (unknown) when permissions are insufficient
	if posture.AccessControl.TwoFactorRequired != nil {
		t.Errorf("TwoFactorRequired = %v, want nil (unknown)", posture.AccessControl.TwoFactorRequired)
	}

	// Repository metrics should still work
	if posture.Scope.RepositoriesCoverage != 100 {
		t.Errorf("RepositoriesCoverage = %d, want 100", posture.Scope.RepositoriesCoverage)
	}
	if posture.Posture.BranchProtectionCoverage != 100 {
		t.Errorf("BranchProtectionCoverage = %d, want 100", posture.Posture.BranchProtectionCoverage)
	}
}
