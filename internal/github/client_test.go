package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSecuritySettings(t *testing.T) {
	tests := []struct {
		name         string
		repoResponse string
		repoStatus   int
		codeResponse string
		codeStatus   int
		wantSettings SecuritySettings
	}{
		{
			name: "all features enabled",
			repoResponse: `{
				"security_and_analysis": {
					"secret_scanning": {"status": "enabled"},
					"secret_scanning_push_protection": {"status": "enabled"},
					"dependabot_security_updates": {"status": "enabled"}
				}
			}`,
			repoStatus:   http.StatusOK,
			codeResponse: `{"state": "configured"}`,
			codeStatus:   http.StatusOK,
			wantSettings: SecuritySettings{
				SecretScanning:               true,
				SecretScanningPushProtection: true,
				DependabotSecurityUpdates:    true,
				CodeScanningEnabled:          true,
			},
		},
		{
			name: "all features disabled",
			repoResponse: `{
				"security_and_analysis": {
					"secret_scanning": {"status": "disabled"},
					"secret_scanning_push_protection": {"status": "disabled"},
					"dependabot_security_updates": {"status": "disabled"}
				}
			}`,
			repoStatus:   http.StatusOK,
			codeResponse: `{"state": "not-configured"}`,
			codeStatus:   http.StatusOK,
			wantSettings: SecuritySettings{
				SecretScanning:               false,
				SecretScanningPushProtection: false,
				DependabotSecurityUpdates:    false,
				CodeScanningEnabled:          false,
			},
		},
		{
			name: "partial features",
			repoResponse: `{
				"security_and_analysis": {
					"secret_scanning": {"status": "enabled"},
					"secret_scanning_push_protection": {"status": "disabled"}
				}
			}`,
			repoStatus:   http.StatusOK,
			codeResponse: `{"state": "configured"}`,
			codeStatus:   http.StatusOK,
			wantSettings: SecuritySettings{
				SecretScanning:               true,
				SecretScanningPushProtection: false,
				DependabotSecurityUpdates:    false,
				CodeScanningEnabled:          true,
			},
		},
		{
			name:         "repo not found",
			repoResponse: `{"message": "Not Found"}`,
			repoStatus:   http.StatusNotFound,
			codeResponse: ``,
			codeStatus:   http.StatusNotFound,
			wantSettings: SecuritySettings{},
		},
		{
			name:         "no security_and_analysis field",
			repoResponse: `{"name": "test-repo"}`,
			repoStatus:   http.StatusOK,
			codeResponse: `{"state": "not-configured"}`,
			codeStatus:   http.StatusOK,
			wantSettings: SecuritySettings{},
		},
		{
			name: "code scanning 404",
			repoResponse: `{
				"security_and_analysis": {
					"secret_scanning": {"status": "enabled"}
				}
			}`,
			repoStatus:   http.StatusOK,
			codeResponse: `{"message": "Advanced Security must be enabled"}`,
			codeStatus:   http.StatusNotFound,
			wantSettings: SecuritySettings{
				SecretScanning:      true,
				CodeScanningEnabled: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/repos/owner/repo":
					w.WriteHeader(tt.repoStatus)
					_, _ = w.Write([]byte(tt.repoResponse))
				case "/repos/owner/repo/code-scanning/default-setup":
					w.WriteHeader(tt.codeStatus)
					_, _ = w.Write([]byte(tt.codeResponse))
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := NewClientWithHTTP(server.Client(), server.URL)
			settings, err := client.FetchSecuritySettings(context.Background(), "owner", "repo")

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if settings.SecretScanning != tt.wantSettings.SecretScanning {
				t.Errorf("SecretScanning = %v, want %v", settings.SecretScanning, tt.wantSettings.SecretScanning)
			}
			if settings.SecretScanningPushProtection != tt.wantSettings.SecretScanningPushProtection {
				t.Errorf("SecretScanningPushProtection = %v, want %v", settings.SecretScanningPushProtection, tt.wantSettings.SecretScanningPushProtection)
			}
			if settings.DependabotSecurityUpdates != tt.wantSettings.DependabotSecurityUpdates {
				t.Errorf("DependabotSecurityUpdates = %v, want %v", settings.DependabotSecurityUpdates, tt.wantSettings.DependabotSecurityUpdates)
			}
			if settings.CodeScanningEnabled != tt.wantSettings.CodeScanningEnabled {
				t.Errorf("CodeScanningEnabled = %v, want %v", settings.CodeScanningEnabled, tt.wantSettings.CodeScanningEnabled)
			}
		})
	}
}

func TestCheckCodeScanning(t *testing.T) {
	tests := []struct {
		name     string
		response string
		status   int
		want     bool
	}{
		{
			name:     "configured",
			response: `{"state": "configured"}`,
			status:   http.StatusOK,
			want:     true,
		},
		{
			name:     "not configured",
			response: `{"state": "not-configured"}`,
			status:   http.StatusOK,
			want:     false,
		},
		{
			name:     "404 error",
			response: `{"message": "Not Found"}`,
			status:   http.StatusNotFound,
			want:     false,
		},
		{
			name:     "invalid json",
			response: `not json`,
			status:   http.StatusOK,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/owner/repo/code-scanning/default-setup" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := NewClientWithHTTP(server.Client(), server.URL)
			got := client.checkCodeScanning(context.Background(), "owner", "repo")

			if got != tt.want {
				t.Errorf("checkCodeScanning() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetchSecuritySettings_Headers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers are set correctly
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept header = %q, want %q", r.Header.Get("Accept"), "application/vnd.github+json")
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("X-GitHub-Api-Version header = %q, want %q", r.Header.Get("X-GitHub-Api-Version"), "2022-11-28")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, _ = client.FetchSecuritySettings(context.Background(), "owner", "repo")
}

// GraphQL HTTP-level tests

func TestFetchOrgSecurity_Success(t *testing.T) {
	// Test successful fetch using REST for 2FA
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/test-org" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"two_factor_requirement_enabled": true,
			})
		} else {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	security, err := client.FetchOrgSecurity(context.Background(), "test-org")

	if err != nil {
		t.Fatalf("FetchOrgSecurity() error: %v", err)
	}

	if security.TwoFactorRequired == nil || *security.TwoFactorRequired != true {
		t.Errorf("TwoFactorRequired = %v, want true", security.TwoFactorRequired)
	}
}

func TestFetchOrgSecurity_TwoFactorDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/test-org" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"two_factor_requirement_enabled": false,
			})
		} else {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	security, err := client.FetchOrgSecurity(context.Background(), "test-org")

	if err != nil {
		t.Fatalf("FetchOrgSecurity() error: %v", err)
	}

	if security.TwoFactorRequired == nil || *security.TwoFactorRequired != false {
		t.Errorf("TwoFactorRequired = %v, want false", security.TwoFactorRequired)
	}
}

func TestFetchOrgSecurity_PermissionError(t *testing.T) {
	// Test that errors result in nil fields (graceful degradation)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/test-org" {
			// REST API returns 403 - no permission for 2FA
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Must have admin rights to Repository",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	security, err := client.FetchOrgSecurity(context.Background(), "test-org")

	// Should NOT return an error - should return partial data
	if err != nil {
		t.Fatalf("FetchOrgSecurity() error: %v, want nil (graceful degradation)", err)
	}

	// 2FA should be nil (unknown) due to permission error
	if security.TwoFactorRequired != nil {
		t.Errorf("TwoFactorRequired = %v, want nil", security.TwoFactorRequired)
	}
}

func TestFetchRepositories_Pagination(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		// Read request to check cursor
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		var response map[string]interface{}

		if callCount == 1 {
			// First page
			if strings.Contains(bodyStr, "cursor") && !strings.Contains(bodyStr, `"cursor":null`) {
				t.Error("First request should have null cursor")
			}
			response = map[string]interface{}{
				"data": map[string]interface{}{
					"organization": map[string]interface{}{
						"repositories": map[string]interface{}{
							"nodes": []map[string]interface{}{
								{"name": "repo1", "owner": map[string]interface{}{"login": "org"}},
								{"name": "repo2", "owner": map[string]interface{}{"login": "org"}},
							},
							"pageInfo": map[string]interface{}{
								"hasNextPage": true,
								"endCursor":   "cursor123",
							},
						},
					},
				},
			}
		} else {
			// Second page
			if !strings.Contains(bodyStr, "cursor123") {
				t.Error("Second request should have cursor from first response")
			}
			response = map[string]interface{}{
				"data": map[string]interface{}{
					"organization": map[string]interface{}{
						"repositories": map[string]interface{}{
							"nodes": []map[string]interface{}{
								{"name": "repo3", "owner": map[string]interface{}{"login": "org"}},
							},
							"pageInfo": map[string]interface{}{
								"hasNextPage": false,
								"endCursor":   "",
							},
						},
					},
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql")

	var allRepos []Repository
	err := client.FetchRepositories(context.Background(), "org", func(repos []Repository) error {
		allRepos = append(allRepos, repos...)
		return nil
	})

	if err != nil {
		t.Fatalf("FetchRepositories() error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("Expected 2 GraphQL calls, got %d", callCount)
	}

	if len(allRepos) != 3 {
		t.Errorf("Expected 3 repos, got %d", len(allRepos))
	}
}

func TestFetchOrgSecurity_RateLimitError(t *testing.T) {
	// Rate limit errors should result in graceful degradation (nil values)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1234567890")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "API rate limit exceeded",
		})
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	security, err := client.FetchOrgSecurity(context.Background(), "test-org")

	// Should gracefully degrade - return nil values instead of error
	if err != nil {
		t.Fatalf("FetchOrgSecurity() error: %v, want graceful degradation", err)
	}

	// 2FA should be nil due to rate limiting
	if security.TwoFactorRequired != nil {
		t.Errorf("TwoFactorRequired = %v, want nil", security.TwoFactorRequired)
	}
}

func TestFetchOrgSecurity_ContextCancellation(t *testing.T) {
	// Context cancellation during REST call should result in nil values (graceful degradation)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay response to trigger context cancellation
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	security, err := client.FetchOrgSecurity(ctx, "test-org")

	// Should gracefully degrade - REST call times out but we return nil values
	if err != nil {
		t.Fatalf("FetchOrgSecurity() error: %v, want graceful degradation", err)
	}

	// 2FA should be nil due to timeout
	if security.TwoFactorRequired != nil {
		t.Errorf("TwoFactorRequired = %v, want nil", security.TwoFactorRequired)
	}
}

func TestFetchRepositories_BranchProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query includes branch protection fields
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		expectedFields := []string{
			"defaultBranchRef",
			"branchProtectionRule",
			"requiresApprovingReviews",
			"dismissesStaleReviews",
			"requiresStatusChecks",
			"requiresCommitSignatures",
			"isAdminEnforced",
		}
		for _, field := range expectedFields {
			if !strings.Contains(bodyStr, field) {
				t.Errorf("Query missing field %q", field)
			}
		}

		response := map[string]interface{}{
			"data": map[string]interface{}{
				"organization": map[string]interface{}{
					"repositories": map[string]interface{}{
						"nodes": []map[string]interface{}{
							{
								"name":  "protected-repo",
								"owner": map[string]interface{}{"login": "org"},
								"defaultBranchRef": map[string]interface{}{
									"name": "main",
									"branchProtectionRule": map[string]interface{}{
										"requiresApprovingReviews":     true,
										"requiredApprovingReviewCount": 2,
										"dismissesStaleReviews":        true,
										"requiresCodeOwnerReviews":     true,
										"requiresStatusChecks":         true,
										"requiresCommitSignatures":     false,
										"isAdminEnforced":              true,
									},
								},
								"hasVulnerabilityAlertsEnabled": true,
							},
						},
						"pageInfo": map[string]interface{}{
							"hasNextPage": false,
							"endCursor":   "",
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql")

	var repos []Repository
	err := client.FetchRepositories(context.Background(), "org", func(r []Repository) error {
		repos = r
		return nil
	})

	if err != nil {
		t.Fatalf("FetchRepositories() error: %v", err)
	}

	if len(repos) != 1 {
		t.Fatalf("Expected 1 repo, got %d", len(repos))
	}

	repo := repos[0]
	if repo.Name != "protected-repo" {
		t.Errorf("Name = %q, want %q", repo.Name, "protected-repo")
	}
	if repo.DefaultBranchRef.BranchProtectionRule == nil {
		t.Fatal("BranchProtectionRule is nil")
	}

	rule := repo.DefaultBranchRef.BranchProtectionRule
	if !rule.RequiresApprovingReviews {
		t.Error("RequiresApprovingReviews should be true")
	}
	if rule.RequiredApprovingReviewCount != 2 {
		t.Errorf("RequiredApprovingReviewCount = %d, want 2", rule.RequiredApprovingReviewCount)
	}
	if !rule.DismissesStaleReviews {
		t.Error("DismissesStaleReviews should be true")
	}
	if !rule.IsAdminEnforced {
		t.Error("IsAdminEnforced should be true")
	}
}
