package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

func TestFetchSecuritySettings(t *testing.T) {
	tests := []struct {
		name             string
		repoResponse     string
		repoStatus       int
		codeResponse     string
		codeStatus       int
		analysesResponse string
		analysesStatus   int
		wantSettings     SecuritySettings
		wantErr          bool
		wantHidden       bool
		wantCodeUnknown  bool
	}{
		{
			name: "all features enabled",
			repoResponse: `{
				"name": "repo",
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
				"name": "repo",
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
				"name": "repo",
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
			name: "advanced setup detected via analyses",
			repoResponse: `{
				"name": "repo",
				"security_and_analysis": {
					"secret_scanning": {"status": "disabled"}
				}
			}`,
			repoStatus:       http.StatusOK,
			codeResponse:     `{"state": "not-configured"}`,
			codeStatus:       http.StatusOK,
			analysesResponse: `[{"ref": "refs/heads/main"}]`,
			analysesStatus:   http.StatusOK,
			wantSettings: SecuritySettings{
				CodeScanningEnabled: true,
			},
		},
		{
			// A repository GitHub could not return leaves every setting
			// unknown rather than reading as every feature disabled.
			name:         "repo not found",
			repoResponse: `{"message": "Not Found"}`,
			repoStatus:   http.StatusNotFound,
			wantErr:      true,
		},
		{
			name:         "server error",
			repoResponse: `{"message": "Server Error"}`,
			repoStatus:   http.StatusBadGateway,
			wantErr:      true,
		},
		{
			name:         "malformed repository body",
			repoResponse: `{"name": "repo", "security_and_analysis":`,
			repoStatus:   http.StatusOK,
			wantErr:      true,
		},
		{
			name:         "repository body without a name",
			repoResponse: `{}`,
			repoStatus:   http.StatusOK,
			wantErr:      true,
		},
		{
			name:         "no security_and_analysis field",
			repoResponse: `{"name": "test-repo"}`,
			repoStatus:   http.StatusOK,
			codeResponse: `{"state": "not-configured"}`,
			codeStatus:   http.StatusOK,
			wantSettings: SecuritySettings{},
			wantHidden:   true,
		},
		{
			name: "code scanning 404",
			repoResponse: `{
				"name": "repo",
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
		{
			name: "code scanning server error",
			repoResponse: `{
				"name": "repo",
				"security_and_analysis": {
					"secret_scanning": {"status": "enabled"}
				}
			}`,
			repoStatus:      http.StatusOK,
			codeResponse:    `{"message": "Server Error"}`,
			codeStatus:      http.StatusInternalServerError,
			wantSettings:    SecuritySettings{SecretScanning: true},
			wantCodeUnknown: true,
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
				case "/repos/owner/repo/code-scanning/analyses":
					status := tt.analysesStatus
					if status == 0 {
						status = http.StatusNotFound
					}
					w.WriteHeader(status)
					_, _ = w.Write([]byte(tt.analysesResponse))
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := NewClientWithHTTP(server.Client(), server.URL)
			settings, err := client.FetchSecuritySettings(context.Background(), "owner", "repo")

			if tt.wantErr {
				if err == nil {
					t.Fatalf("settings = %+v, want an error", settings)
				}
				return
			}
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
			if hidden := settings.AnalysisErr != nil; hidden != tt.wantHidden {
				t.Errorf("AnalysisErr = %v, want hidden %v", settings.AnalysisErr, tt.wantHidden)
			}
			if tt.wantHidden && componentsdk.Classify(settings.AnalysisErr) != componentsdk.CodePermissionDenied {
				t.Errorf("hidden security_and_analysis code = %s, want permission_denied", componentsdk.Classify(settings.AnalysisErr))
			}
			if unknown := settings.CodeScanningErr != nil; unknown != tt.wantCodeUnknown {
				t.Errorf("CodeScanningErr = %v, want unknown %v", settings.CodeScanningErr, tt.wantCodeUnknown)
			}
		})
	}
}

func TestFetchSecuritySettings_PermissionDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message": "Must have admin rights to Repository"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.FetchSecuritySettings(context.Background(), "owner", "repo")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestCheckCodeScanning(t *testing.T) {
	tests := []struct {
		name               string
		response           string
		status             int
		analysesResponse   string
		analysesStatus     int
		want               bool
		wantPermissionDeny bool
		wantErrorMessage   string
		wantUnknown        bool
	}{
		{
			name:               "configured",
			response:           `{"state": "configured"}`,
			status:             http.StatusOK,
			want:               true,
			wantPermissionDeny: false,
		},
		{
			name:               "advanced setup detected via analyses",
			response:           `{"state": "not-configured"}`,
			status:             http.StatusOK,
			analysesResponse:   `[{"ref": "refs/heads/main"}]`,
			analysesStatus:     http.StatusOK,
			want:               true,
			wantPermissionDeny: false,
		},
		{
			name:               "not configured",
			response:           `{"state": "not-configured"}`,
			status:             http.StatusOK,
			want:               false,
			wantPermissionDeny: false,
		},
		{
			name:               "404 error",
			response:           `{"message": "Not Found"}`,
			status:             http.StatusNotFound,
			want:               false,
			wantPermissionDeny: false,
		},
		{
			name:               "403 permission denied",
			response:           `{"message": "Must have admin rights to Repository"}`,
			status:             http.StatusForbidden,
			want:               false,
			wantPermissionDeny: true,
			wantErrorMessage:   "Must have admin rights to Repository",
			wantUnknown:        true,
		},
		{
			name:               "403 GHAS not enabled",
			response:           `{"message": "Advanced Security must be enabled for this repository to use code scanning."}`,
			status:             http.StatusForbidden,
			want:               false,
			wantPermissionDeny: true,
			wantErrorMessage:   "Advanced Security must be enabled for this repository to use code scanning.",
		},
		{
			name:               "invalid json",
			response:           `not json`,
			status:             http.StatusOK,
			want:               false,
			wantPermissionDeny: false,
			wantUnknown:        true,
		},
		{
			name:        "default setup body without a state",
			response:    `{}`,
			status:      http.StatusOK,
			wantUnknown: true,
		},
		{
			name:             "analyses server error",
			response:         `{"state": "not-configured"}`,
			status:           http.StatusOK,
			analysesResponse: `{"message": "Server Error"}`,
			analysesStatus:   http.StatusInternalServerError,
			wantUnknown:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/repos/owner/repo/code-scanning/default-setup":
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.response))
				case "/repos/owner/repo/code-scanning/analyses":
					status := tt.analysesStatus
					if status == 0 {
						status = http.StatusNotFound
					}
					w.WriteHeader(status)
					_, _ = w.Write([]byte(tt.analysesResponse))
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
			}))
			defer server.Close()

			client := NewClientWithHTTP(server.Client(), server.URL)
			result := client.checkCodeScanning(context.Background(), "owner", "repo")

			if result.enabled != tt.want {
				t.Errorf("checkCodeScanning() enabled = %v, want %v", result.enabled, tt.want)
			}
			if result.permissionDenied != tt.wantPermissionDeny {
				t.Errorf("checkCodeScanning() permissionDenied = %v, want %v", result.permissionDenied, tt.wantPermissionDeny)
			}
			if result.errorMessage != tt.wantErrorMessage {
				t.Errorf("checkCodeScanning() errorMessage = %q, want %q", result.errorMessage, tt.wantErrorMessage)
			}
			if unknown := result.err != nil; unknown != tt.wantUnknown {
				t.Errorf("checkCodeScanning() err = %v, want unknown %v", result.err, tt.wantUnknown)
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
				"login":                          "test-org",
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
				"login":                          "test-org",
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
	// The organization read is the sign-in, so a refusal fails it rather than
	// reading as an unknown setting.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/test-org" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Resource protected by organization SAML enforcement.",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.FetchOrgSecurity(context.Background(), "test-org")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("FetchOrgSecurity() error = %v, want ErrPermissionDenied", err)
	}
	if got := componentsdk.Classify(err); got != componentsdk.CodePermissionDenied {
		t.Errorf("Classify() = %s, want permission_denied", got)
	}
}

func TestFetchOrgSecurity_RejectedCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message": "Bad credentials"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.FetchOrgSecurity(context.Background(), "test-org")
	if got := componentsdk.Classify(err); got != componentsdk.CodeAuthFailed {
		t.Fatalf("Classify(%v) = %s, want auth_failed", err, got)
	}
}

func TestFetchOrgSecurity_UnknownOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.FetchOrgSecurity(context.Background(), "no-such-org")
	if got := componentsdk.Classify(err); got != componentsdk.CodeConfigInvalid {
		t.Fatalf("Classify(%v) = %s, want config_invalid", err, got)
	}
}

func TestFetchOrgSecurity_HiddenTwoFactorSetting(t *testing.T) {
	// GitHub leaves the setting out for callers that are not organization
	// owners; the setting is then unknown.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		_, _ = w.Write([]byte(`{"login": "test-org"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	security, err := client.FetchOrgSecurity(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("FetchOrgSecurity() error: %v", err)
	}
	if security.TwoFactorRequired != nil {
		t.Errorf("TwoFactorRequired = %v, want nil", *security.TwoFactorRequired)
	}
	if strings.Join(security.Credential.Scopes, ",") != "repo,read:org" || security.Credential.Kind != "token" {
		t.Errorf("credential = %+v, want a token with its OAuth scopes", security.Credential)
	}
}

func TestFetchOrgSecurity_BodyWithoutLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.FetchOrgSecurity(context.Background(), "test-org")
	if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
		t.Fatalf("Classify(%v) = %s, want invalid_response", err, got)
	}
}

func TestFetchOrgSecurity_RepositoryCount(t *testing.T) {
	tests := []struct {
		name string
		body map[string]any
		want *int
	}{
		{
			// total_private_repos leaves internal repositories out, so it is
			// not counted.
			name: "owner",
			body: map[string]any{"login": "test-org", "public_repos": 18, "owned_private_repos": 15, "total_private_repos": 5},
			want: ptrInt(33),
		},
		{
			name: "not an owner",
			body: map[string]any{"login": "test-org", "public_repos": 18},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(tt.body)
			}))
			defer server.Close()

			security, err := NewClientWithHTTP(server.Client(), server.URL).FetchOrgSecurity(context.Background(), "test-org")
			if err != nil {
				t.Fatalf("FetchOrgSecurity() error: %v", err)
			}
			switch {
			case tt.want == nil && security.RepositoryCount != nil:
				t.Errorf("RepositoryCount = %d, want nil", *security.RepositoryCount)
			case tt.want != nil && (security.RepositoryCount == nil || *security.RepositoryCount != *tt.want):
				t.Errorf("RepositoryCount = %v, want %d", security.RepositoryCount, *tt.want)
			}
		})
	}
}

func ptrInt(v int) *int { return &v }

// installationReposPage serves one page of GET /installation/repositories,
// linking to page 2 when next is set.
func installationReposPage(w http.ResponseWriter, serverURL, selection string, names []string, next bool) {
	repos := make([]any, 0, len(names))
	for _, name := range names {
		repos = append(repos, map[string]any{"name": name, "full_name": "test-org/" + name})
	}
	if next {
		w.Header().Set("Link", fmt.Sprintf(`<%s/installation/repositories?per_page=100&page=2>; rel="next"`, serverURL))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 2, "repository_selection": selection, "repositories": repos})
}

func TestFetchInstallationRepositories_FollowsEveryPage(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/repositories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("page") == "" {
			installationReposPage(w, server.URL, RepositorySelectionSelected, []string{"Repo-One"}, true)
			return
		}
		installationReposPage(w, server.URL, RepositorySelectionSelected, []string{"repo-two"}, false)
	}))
	defer server.Close()

	installed, err := NewClientWithHTTP(server.Client(), server.URL).FetchInstallationRepositories(context.Background())
	if err != nil {
		t.Fatalf("FetchInstallationRepositories() error: %v", err)
	}
	if installed.Selection != RepositorySelectionSelected || len(installed.Names) != 2 || !installed.Names["repo-one"] || !installed.Names["repo-two"] {
		t.Errorf("installed = %+v, want selected with repo-one and repo-two", installed)
	}
}

func TestFetchInstallationRepositories_AllNeedsOnePage(t *testing.T) {
	requests := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		installationReposPage(w, server.URL, RepositorySelectionAll, []string{"repo-one"}, true)
	}))
	defer server.Close()

	installed, err := NewClientWithHTTP(server.Client(), server.URL).FetchInstallationRepositories(context.Background())
	if err != nil {
		t.Fatalf("FetchInstallationRepositories() error: %v", err)
	}
	if installed.Selection != RepositorySelectionAll || installed.Names != nil || requests != 1 {
		t.Errorf("installed = %+v after %d requests, want all after one", installed, requests)
	}
}

func TestFetchInstallationRepositories_WithoutASelection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":0,"repositories":[]}`))
	}))
	defer server.Close()

	_, err := NewClientWithHTTP(server.Client(), server.URL).FetchInstallationRepositories(context.Background())
	if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
		t.Fatalf("Classify(%v) = %s, want invalid_response", err, got)
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
	_, err := client.FetchOrgSecurity(context.Background(), "test-org")
	if got := componentsdk.Classify(err); got != componentsdk.CodeRateLimited {
		t.Fatalf("Classify(%v) = %s, want rate_limited", err, got)
	}
	if errors.Is(err, ErrPermissionDenied) {
		t.Error("a rate-limited 403 should not read as a permission denial")
	}
}

func TestFetchOrgSecurity_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay response to trigger context cancellation
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"login": "test-org"})
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.FetchOrgSecurity(ctx, "test-org")
	if got := componentsdk.Classify(err); got != componentsdk.CodeTimeout {
		t.Fatalf("Classify(%v) = %s, want timeout", err, got)
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
			"isArchived",
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
								"name":       "protected-repo",
								"owner":      map[string]interface{}{"login": "org"},
								"isArchived": false,
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
	if repo.IsArchived {
		t.Error("IsArchived = true, want false")
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

func TestGetOrgMembership_IncludesDisplayNames(t *testing.T) {
	graphqlCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/graphql" {
			graphqlCalls++
			body, _ := io.ReadAll(r.Body)
			var response map[string]interface{}
			if graphqlCalls == 1 {
				response = map[string]interface{}{
					"data": map[string]interface{}{
						"organization": map[string]interface{}{
							"membersWithRole": map[string]interface{}{
								"nodes": []map[string]interface{}{
									{"login": "alice", "name": "Alice Adams"},
								},
								"pageInfo": map[string]interface{}{"hasNextPage": true, "endCursor": "cursor-a"},
							},
						},
					},
				}
			} else {
				if !strings.Contains(string(body), "cursor-a") {
					t.Error("second GraphQL request should carry the first page's cursor")
				}
				response = map[string]interface{}{
					"data": map[string]interface{}{
						"organization": map[string]interface{}{
							"membersWithRole": map[string]interface{}{
								"nodes": []map[string]interface{}{
									{"login": "bob", "name": nil},
									{"login": "dana", "name": ""},
								},
								"pageInfo": map[string]interface{}{"hasNextPage": false, "endCursor": ""},
							},
						},
					},
				}
			}
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		switch {
		case r.URL.Path == "/orgs/test-org/members" && r.URL.Query().Get("role") == "admin":
			_, _ = w.Write([]byte(`[{"login":"alice"}]`))
		case r.URL.Path == "/orgs/test-org/members" && r.URL.Query().Get("filter") == "2fa_disabled":
			_, _ = w.Write([]byte(`[{"login":"bob"}]`))
		case r.URL.Path == "/orgs/test-org/members":
			_, _ = w.Write([]byte(`[{"login":"alice"},{"login":"bob"},{"login":"dana"}]`))
		case r.URL.Path == "/orgs/test-org/outside_collaborators":
			_, _ = w.Write([]byte(`[{"login":"carol"},{"login":"eve"}]`))
		case r.URL.Path == "/orgs/test-org/invitations":
			_, _ = w.Write([]byte(`[{}]`))
		case r.URL.Path == "/users/carol":
			_, _ = w.Write([]byte(`{"login":"carol","name":"Carol Chen"}`))
		case r.URL.Path == "/users/eve":
			_, _ = w.Write([]byte(`{"login":"eve","name":null}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql")

	membership, err := client.GetOrgMembership(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("GetOrgMembership() error: %v", err)
	}

	if graphqlCalls != 2 {
		t.Errorf("Expected 2 GraphQL calls, got %d", graphqlCalls)
	}
	if len(membership.Members) != 3 {
		t.Fatalf("Members = %v, want 3 logins", membership.Members)
	}
	if membership.PendingInvitations != 1 {
		t.Errorf("PendingInvitations = %d, want 1", membership.PendingInvitations)
	}
	if len(membership.Names) != 2 || membership.Names["alice"] != "Alice Adams" || membership.Names["carol"] != "Carol Chen" {
		t.Errorf(`Names = %v, want map[alice:Alice Adams carol:Carol Chen]`, membership.Names)
	}
	if len(membership.NamesIncomplete) != 0 {
		t.Errorf("NamesIncomplete = %v, want none", membership.NamesIncomplete)
	}
}

func TestGetOrgMembership_NoGraphQLLeavesNamesNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)

	membership, err := client.GetOrgMembership(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("GetOrgMembership() error: %v", err)
	}
	if membership.Names != nil {
		t.Errorf("Names = %v, want nil when GraphQL is unavailable", membership.Names)
	}
	if len(membership.NamesIncomplete) != 1 {
		t.Errorf("NamesIncomplete = %v, want the bulk-query failure recorded", membership.NamesIncomplete)
	}
}

func TestCollaboratorNames_CapAndAbort(t *testing.T) {
	userCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		userCalls++
		switch r.URL.Path {
		case "/users/ghost":
			w.WriteHeader(http.StatusNotFound)
		case "/users/boom":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			_, _ = fmt.Fprintf(w, `{"login":%q,"name":"Someone"}`, strings.TrimPrefix(r.URL.Path, "/users/"))
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)

	lookup := client.collaboratorNames(context.Background(), []string{"ghost", "ok", "boom", "never"})
	if userCalls != 3 {
		t.Errorf("lookup calls = %d, want 3 (404 skipped, abort on 500)", userCalls)
	}
	if len(lookup.names) != 1 || lookup.names["ok"] != "Someone" {
		t.Errorf("names = %v, want map[ok:Someone]", lookup.names)
	}
	if len(lookup.incomplete) != 1 || !strings.Contains(lookup.incomplete[0], "aborted") {
		t.Errorf("incomplete = %v, want one abort reason", lookup.incomplete)
	}
	if strings.Join(lookup.unread, ",") != "boom,never" || lookup.err == nil {
		t.Errorf("unread = %v (err %v), want the failed login and the rest with the error", lookup.unread, lookup.err)
	}

	many := make([]string, CollaboratorNameLookupCap+5)
	for i := range many {
		many[i] = fmt.Sprintf("user%d", i)
	}
	userCalls = 0
	lookup = client.collaboratorNames(context.Background(), many)
	if userCalls != CollaboratorNameLookupCap {
		t.Errorf("lookup calls = %d, want cap %d", userCalls, CollaboratorNameLookupCap)
	}
	if len(lookup.names) != CollaboratorNameLookupCap {
		t.Errorf("names len = %d, want %d", len(lookup.names), CollaboratorNameLookupCap)
	}
	if len(lookup.incomplete) != 1 || !strings.Contains(lookup.incomplete[0], "capped") {
		t.Errorf("incomplete = %v, want one cap reason", lookup.incomplete)
	}
}
