//go:build e2e
// +build e2e

// End-to-end tests that make real HTTP requests to GitHub API.
// Run with: go test -tags=e2e ./internal/collector/...
//
// Required environment variables:
//   - GITHUB_TOKEN: Personal access token with repo and read:org scopes
//   - GITHUB_ORG: Organization name to test against
//
// Optional environment variables:
//   - GITHUB_APP_ID: GitHub App ID (alternative to token)
//   - GITHUB_APP_INSTALLATION_ID: GitHub App installation ID
//   - GITHUB_APP_PRIVATE_KEY: GitHub App private key (PEM format)

package collector

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestE2E_RealGitHubCollection(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	org := os.Getenv("GITHUB_ORG")

	if token == "" || org == "" {
		t.Skip("Skipping e2e test: GITHUB_TOKEN and GITHUB_ORG required")
	}

	config := Config{
		Organization: org,
		GitHubToken:  token,
	}

	collector, err := New(config)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	start := time.Now()
	posture, err := collector.Collect(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	t.Logf("Collection completed in %v", elapsed)
	t.Logf("Organization: %s", posture.Organization)
	t.Logf("Schema version: %s", posture.SchemaVersion)
	t.Logf("Collected at: %s", posture.CollectedAt)

	// Verify basic structure
	if posture.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", posture.SchemaVersion, "1.0.0")
	}
	if posture.Organization != org {
		t.Errorf("Organization = %q, want %q", posture.Organization, org)
	}

	// Log metrics
	t.Logf("Repository coverage: %d%%", posture.Scope.RepositoriesCoverage)
	t.Logf("Branch protection coverage: %d%%", posture.Posture.BranchProtectionCoverage)
	t.Logf("Security features coverage: %d%%", posture.Posture.SecurityFeaturesCoverage)
	t.Logf("2FA required: %v", posture.AccessControl.TwoFactorRequired)

	// Output full JSON for inspection
	jsonBytes, err := json.MarshalIndent(posture, "", "  ")
	if err != nil {
		t.Errorf("JSON marshal error: %v", err)
	}
	t.Logf("Full output:\n%s", string(jsonBytes))
}

func TestE2E_RealGitHubWithFilters(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	org := os.Getenv("GITHUB_ORG")

	if token == "" || org == "" {
		t.Skip("Skipping e2e test: GITHUB_TOKEN and GITHUB_ORG required")
	}

	// Test with include patterns
	config := Config{
		Organization:    org,
		GitHubToken:     token,
		IncludePatterns: []string{"*"},
		ExcludePatterns: []string{"*-archive", "deprecated-*"},
	}

	collector, err := New(config)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	posture, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	t.Logf("Repository coverage: %d%%", posture.Scope.RepositoriesCoverage)
	t.Logf("Include patterns: %v", posture.Scope.IncludePatterns)
	t.Logf("Exclude patterns: %v", posture.Scope.ExcludePatterns)
}

func TestE2E_RealGitHubAppAuth(t *testing.T) {
	appID := os.Getenv("GITHUB_APP_ID")
	installationID := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	privateKey := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	org := os.Getenv("GITHUB_ORG")

	if appID == "" || installationID == "" || privateKey == "" || org == "" {
		t.Skip("Skipping e2e test: GITHUB_APP_* and GITHUB_ORG required")
	}

	// Parse IDs
	var appIDInt, installationIDInt int64
	if _, err := parseIntEnv("GITHUB_APP_ID", &appIDInt); err != nil {
		t.Fatalf("Invalid GITHUB_APP_ID: %v", err)
	}
	if _, err := parseIntEnv("GITHUB_APP_INSTALLATION_ID", &installationIDInt); err != nil {
		t.Fatalf("Invalid GITHUB_APP_INSTALLATION_ID: %v", err)
	}

	config := Config{
		Organization:   org,
		AppID:          appIDInt,
		InstallationID: installationIDInt,
		PrivateKey:     privateKey,
	}

	collector, err := New(config)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	start := time.Now()
	posture, err := collector.Collect(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	t.Logf("Collection completed with App auth in %v", elapsed)
	t.Logf("Organization: %s", posture.Organization)
	t.Logf("Schema version: %s", posture.SchemaVersion)
	t.Logf("Collected at: %s", posture.CollectedAt)

	// Log metrics
	t.Logf("Repository coverage: %d%%", posture.Scope.RepositoriesCoverage)
	t.Logf("Branch protection coverage: %d%%", posture.Posture.BranchProtectionCoverage)
	t.Logf("Security features coverage: %d%%", posture.Posture.SecurityFeaturesCoverage)
	t.Logf("2FA required: %v", posture.AccessControl.TwoFactorRequired)

	// Output full JSON for inspection
	jsonBytes, err := json.MarshalIndent(posture, "", "  ")
	if err != nil {
		t.Errorf("JSON marshal error: %v", err)
	}
	t.Logf("Full output:\n%s", string(jsonBytes))
}

func TestE2E_RealGitHubRateLimiting(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	org := os.Getenv("GITHUB_ORG")

	if token == "" || org == "" {
		t.Skip("Skipping e2e test: GITHUB_TOKEN and GITHUB_ORG required")
	}

	// Run collection multiple times to test rate limit handling
	config := Config{
		Organization: org,
		GitHubToken:  token,
	}

	collector, err := New(config)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Run 3 collections in quick succession
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

		start := time.Now()
		posture, err := collector.Collect(ctx)
		elapsed := time.Since(start)

		cancel()

		if err != nil {
			t.Fatalf("Collect() run %d error: %v", i+1, err)
		}

		t.Logf("Run %d completed in %v, coverage: %d%%",
			i+1, elapsed, posture.Scope.RepositoriesCoverage)
	}
}

func TestE2E_RealGitHubTimeout(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	org := os.Getenv("GITHUB_ORG")

	if token == "" || org == "" {
		t.Skip("Skipping e2e test: GITHUB_TOKEN and GITHUB_ORG required")
	}

	config := Config{
		Organization: org,
		GitHubToken:  token,
	}

	collector, err := New(config)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Very short timeout - should fail
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err = collector.Collect(ctx)
	if err == nil {
		t.Log("Collection succeeded despite very short timeout (fast API response)")
	} else {
		t.Logf("Collection failed as expected with short timeout: %v", err)
	}
}

// parseIntEnv parses an environment variable as int64.
func parseIntEnv(name string, dst *int64) (bool, error) {
	val := os.Getenv(name)
	if val == "" {
		return false, nil
	}

	var n int64
	for _, c := range val {
		if c < '0' || c > '9' {
			return false, nil
		}
		n = n*10 + int64(c-'0')
	}
	*dst = n
	return true, nil
}
