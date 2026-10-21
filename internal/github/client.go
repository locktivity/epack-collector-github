package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/locktivity/epack/componentsdk"
	"golang.org/x/oauth2"
)

// ErrPermissionDenied is returned when the API returns 403 Forbidden.
// This typically indicates missing permissions on the GitHub App or token.
var ErrPermissionDenied = errors.New("permission denied")

// GitHubClient defines the interface for GitHub API operations.
// This interface allows for easy mocking in tests.
type GitHubClient interface {
	FetchOrgSecurity(ctx context.Context, org string) (*OrgSecurity, error)
	FetchRepositories(ctx context.Context, org string, callback func([]Repository) error) error
	FetchSecuritySettings(ctx context.Context, owner, repo string) (*SecuritySettings, error)
	GetBranchRules(ctx context.Context, owner, repo, branch string) ([]BranchRule, error)
	GetRepoRuleset(ctx context.Context, owner, repo string, rulesetID int64) (*Ruleset, error)

	// Audit / internal surfaces.
	GetOrgSettings(ctx context.Context, org string) (*OrgSettings, error)
	ListSecretScanningAlerts(ctx context.Context, owner, repo string) ([]SecretScanningAlert, bool, error)
	ListCodeScanningAlerts(ctx context.Context, owner, repo string) ([]CodeScanningAlert, bool, error)
	ListDependabotAlerts(ctx context.Context, owner, repo string) ([]DependabotAlert, bool, error)
	GetOrgMembership(ctx context.Context, org string) (*OrgMembership, error)
	GetCodeownersInfo(ctx context.Context, owner, repo string, wantHash bool) (present bool, path string, hash string, err error)
	ListOrgHooks(ctx context.Context, org string) ([]Hook, error)
	ListRepoHooks(ctx context.Context, owner, repo string) ([]Hook, error)
	ListRepoDeployKeys(ctx context.Context, owner, repo string) ([]DeployKey, error)
	ListOrgRunners(ctx context.Context, org string) ([]Runner, int, error)
	ListRepoRunners(ctx context.Context, owner, repo string) ([]Runner, int, error)
	ListOrgActionsSecretNames(ctx context.Context, org string) ([]string, int, error)
	ListRepoEnvironments(ctx context.Context, owner, repo string) ([]Environment, int, error)
	ListEnvironmentBranchPolicies(ctx context.Context, owner, repo, environment string) ([]BranchPolicyPattern, error)
	ListEnvironmentProtectionApps(ctx context.Context, owner, repo, environment string) ([]string, error)
	GetOrgAuditLog(ctx context.Context, org, sinceISO string, maxEvents int) ([]AuditEvent, bool, error)
	ListOrgInstallations(ctx context.Context, org string) ([]Installation, int, error)
	ListOrgPATs(ctx context.Context, org string) ([]PATGrant, bool, error)
}

// Client wraps the GitHub GraphQL and REST APIs.
type Client struct {
	httpClient   *http.Client
	baseURL      string // REST API base URL (for testing with httptest)
	graphqlURL   string
	installation *ghinstallation.Transport
}

// Ensure Client implements GitHubClient.
var _ GitHubClient = (*Client)(nil)

// installationTokenOp names the GitHub App's installation token exchange.
// The exchange creates nothing a retry could duplicate, so it is safe.
var installationTokenOp = componentsdk.Operation{Name: "github.installation_token.create", Safe: true}

// NewClient creates a client that sends token on every request through base.
func NewClient(base http.RoundTripper, token string) *Client {
	transport := &oauth2.Transport{
		Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
		Base:   base,
	}
	return &Client{
		httpClient: &http.Client{Transport: transport},
		baseURL:    DefaultBaseURL,
		graphqlURL: DefaultGraphQLURL,
	}
}

// NewClientWithHTTP creates a client with a custom HTTP client and base URL (for testing).
func NewClientWithHTTP(httpClient *http.Client, baseURL string) *Client {
	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
	}
}

// NewClientWithGraphQL creates a client with custom HTTP client, base URL, and GraphQL endpoint (for testing).
func NewClientWithGraphQL(httpClient *http.Client, baseURL, graphqlURL string) *Client {
	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
		graphqlURL: graphqlURL,
	}
}

// NewClientFromApp creates a client using GitHub App authentication.
// This is the recommended authentication method for organization-level access.
// Build base with NameOperation, so the installation token requests count
// under their own name.
func NewClientFromApp(base http.RoundTripper, appID, installationID int64, privateKey []byte) (*Client, error) {
	itr, err := ghinstallation.New(base, appID, installationID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub App transport: %w", err)
	}
	return &Client{
		httpClient:   &http.Client{Transport: itr},
		baseURL:      DefaultBaseURL,
		graphqlURL:   DefaultGraphQLURL,
		installation: itr,
	}, nil
}

// NameOperation names the installation token requests ghinstallation sends,
// for componentsdk.HTTPOptions.NameOperation. When a token expires mid-run,
// ghinstallation refreshes it with the context of the call that needed it,
// so the context alone would count the refresh as that call.
func NameOperation(req *http.Request) (componentsdk.Operation, bool) {
	if req.Method == http.MethodPost && strings.HasPrefix(req.URL.Path, "/app/installations/") && strings.HasSuffix(req.URL.Path, "/access_tokens") {
		return installationTokenOp, true
	}
	return componentsdk.Operation{}, false
}

// do sends one named request and returns the response when GitHub answered
// 200. Any other status comes back as an *APIError.
func (c *Client) do(ctx context.Context, op componentsdk.Operation, method, url string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx, op), method, url, reader)
	if err != nil {
		return nil, err
	}
	setAPIHeaders(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		var httpErr *ghinstallation.HTTPError
		if errors.As(err, &httpErr) {
			return nil, installationTokenError(err)
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, componentsdk.ResponseError(resp, newAPIError(resp, req.URL.Path))
	}
	return resp, nil
}

// getJSON performs a named GET against the REST API and decodes the body
// into out. Errors wrap ErrPermissionDenied and ErrNotFound so callers can
// branch on expected outcomes.
func (c *Client) getJSON(ctx context.Context, op, path string, out any) error {
	resp, err := c.do(ctx, componentsdk.Operation{Name: op}, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding response: %w", trimQuery(path), err))
	}
	return nil
}

// graphQL runs a named query. GraphQL queries are reads sent with POST, so
// they are marked safe to retry.
func (c *Client) graphQL(ctx context.Context, op, query string, variables map[string]any, data any) error {
	if c.graphqlURL == "" {
		return errors.New("graphql client not configured")
	}
	payload, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, componentsdk.Operation{Name: op, Safe: true}, http.MethodPost, c.graphqlURL, payload)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphQLError  `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("graphql: decoding response: %w", err))
	}
	if len(out.Errors) > 0 {
		return componentsdk.ResponseError(resp, newGraphQLError(resp, out.Errors))
	}
	if len(out.Data) == 0 || string(out.Data) == "null" {
		return componentsdk.ResponseError(resp, invalidResponse("graphql response has no data"))
	}
	if err := json.Unmarshal(out.Data, data); err != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("graphql: decoding data: %w", err))
	}
	return nil
}

// FetchRepositories fetches all repositories for an organization with pagination.
// It returns repositories one page at a time via the callback function.
func (c *Client) FetchRepositories(ctx context.Context, org string, callback func([]Repository) error) error {
	var cursor *string
	for {
		var data struct {
			Organization *struct {
				Repositories *struct {
					Nodes    *[]Repository
					PageInfo pageInfo
				}
			}
		}
		if err := c.graphQL(ctx, "github.repositories.list", repositoriesQuery, map[string]any{"org": org, "cursor": cursor}, &data); err != nil {
			return err
		}
		if data.Organization == nil || data.Organization.Repositories == nil || data.Organization.Repositories.Nodes == nil {
			return invalidResponse("graphql repositories response has no repository list")
		}
		page := data.Organization.Repositories
		if err := callback(*page.Nodes); err != nil {
			return err
		}
		if !page.PageInfo.HasNextPage {
			return nil
		}
		next := page.PageInfo.EndCursor
		cursor = &next
	}
}

// OrgSecurity represents organization-level security settings and the
// credential that read them. TwoFactorRequired is nil when GitHub left the
// setting out, which it does unless the caller is an organization owner.
type OrgSecurity struct {
	TwoFactorRequired *bool
	Credential        Credential
}

// Credential kinds.
const (
	CredentialAppInstallation = "app_installation"
	CredentialToken           = "token"
)

// Credential describes what the collector signed in as.
type Credential struct {
	// Kind is CredentialAppInstallation or CredentialToken.
	Kind string
	// ID is the GitHub App's ID. Tokens have none.
	ID string
	// Scopes are the installation's permissions, as name:level, or a classic
	// token's OAuth scopes.
	Scopes []string
}

// FetchOrgSecurity signs in and reads organization-level security settings.
// For a GitHub App it first exchanges the App's key for an installation
// token. Any failure is returned, since nothing else can be read without it.
// A 404 on the organization means it does not exist, so that failure is
// config_invalid.
//
// Note: We intentionally avoid GraphQL for org security settings because
// GitHub Apps cannot access the requiresTwoFactorAuthentication or
// samlIdentityProvider fields even with Organization Administration permission.
// This is a known GitHub API limitation:
// https://github.com/orgs/community/discussions/45063
//
// SSO detection is not supported because:
// - GraphQL samlIdentityProvider has the same permission bug
// - No REST API endpoint returns SSO status
// - The SAML metadata endpoint returns 200 for all orgs regardless of SSO configuration
func (c *Client) FetchOrgSecurity(ctx context.Context, org string) (*OrgSecurity, error) {
	result := &OrgSecurity{}
	if c.installation != nil {
		token, err := c.installation.Token(ctx)
		if err != nil {
			return nil, installationTokenError(err)
		}
		if token == "" {
			return nil, invalidResponse("installation token response has no token")
		}
		result.Credential = Credential{
			Kind:   CredentialAppInstallation,
			ID:     strconv.FormatInt(c.installation.AppID(), 10),
			Scopes: installationScopes(c.installation),
		}
	}

	path := "/orgs/" + org
	resp, err := c.do(ctx, componentsdk.Operation{Name: "github.orgs.get"}, http.MethodGet, c.baseURL+path, nil)
	if errors.Is(err, ErrNotFound) {
		return nil, componentsdk.CodeError(componentsdk.CodeConfigInvalid, fmt.Errorf("organization not found: %w", err))
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Login                       string `json:"login"`
		TwoFactorRequirementEnabled *bool  `json:"two_factor_requirement_enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("%s: decoding response: %w", path, err)
	}
	if body.Login == "" {
		return nil, invalidResponse("%s response has no login", path)
	}
	result.TwoFactorRequired = body.TwoFactorRequirementEnabled
	if c.installation == nil {
		result.Credential = Credential{Kind: CredentialToken, Scopes: splitScopes(resp.Header.Get("X-OAuth-Scopes"))}
	}
	return result, nil
}

// installationScopes lists an installation token's permissions as name:level.
func installationScopes(itr *ghinstallation.Transport) []string {
	perms, err := itr.Permissions()
	if err != nil {
		return nil
	}
	raw, err := json.Marshal(perms)
	if err != nil {
		return nil
	}
	var levels map[string]string
	if json.Unmarshal(raw, &levels) != nil {
		return nil
	}
	scopes := make([]string, 0, len(levels))
	for name, level := range levels {
		scopes = append(scopes, name+":"+level)
	}
	sort.Strings(scopes)
	return scopes
}

func splitScopes(header string) []string {
	var scopes []string
	for _, s := range strings.Split(header, ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// ErrAnalysisHidden explains settings GitHub withholds from callers without
// admin rights.
var ErrAnalysisHidden = componentsdk.CodeError(componentsdk.CodePermissionDenied,
	errors.New("GitHub returns security_and_analysis only to callers with admin rights on the repository"))

// SecuritySettings represents the security settings for a repository.
type SecuritySettings struct {
	SecretScanning               bool
	SecretScanningPushProtection bool
	DependabotSecurityUpdates    bool
	// AnalysisErr is why the three settings above are unknown, such as
	// GitHub leaving out security_and_analysis for a caller without admin
	// rights. Nil means they hold GitHub's answer.
	AnalysisErr error

	CodeScanningEnabled          bool
	CodeScanningPermissionDenied bool
	CodeScanningErrorMessage     string // Actual error message from GitHub API
	// CodeScanningErr is why CodeScanningEnabled is unknown. Nil means it
	// holds the answer.
	CodeScanningErr error
}

// FetchSecuritySettings fetches security settings for a repository via REST
// API. It returns an error when the repository itself could not be read.
func (c *Client) FetchSecuritySettings(ctx context.Context, owner, repo string) (*SecuritySettings, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	var result struct {
		Name                string `json:"name"`
		SecurityAndAnalysis *struct {
			SecretScanning *struct {
				Status string `json:"status"`
			} `json:"secret_scanning"`
			SecretScanningPushProtection *struct {
				Status string `json:"status"`
			} `json:"secret_scanning_push_protection"`
			DependabotSecurityUpdates *struct {
				Status string `json:"status"`
			} `json:"dependabot_security_updates"`
		} `json:"security_and_analysis"`
	}
	if err := c.getJSON(ctx, "github.repos.get", path, &result); err != nil {
		return nil, fmt.Errorf("security settings for %s/%s: %w", owner, repo, err)
	}
	if result.Name == "" {
		return nil, invalidResponse("%s response has no name", path)
	}

	settings := &SecuritySettings{}
	if sa := result.SecurityAndAnalysis; sa != nil {
		if sa.SecretScanning != nil {
			settings.SecretScanning = sa.SecretScanning.Status == StatusEnabled
		}
		if sa.SecretScanningPushProtection != nil {
			settings.SecretScanningPushProtection = sa.SecretScanningPushProtection.Status == StatusEnabled
		}
		if sa.DependabotSecurityUpdates != nil {
			settings.DependabotSecurityUpdates = sa.DependabotSecurityUpdates.Status == StatusEnabled
		}
	} else {
		settings.AnalysisErr = ErrAnalysisHidden
	}

	csResult := c.checkCodeScanning(ctx, owner, repo)
	settings.CodeScanningEnabled = csResult.enabled
	settings.CodeScanningPermissionDenied = csResult.permissionDenied
	settings.CodeScanningErrorMessage = csResult.errorMessage
	settings.CodeScanningErr = csResult.err

	return settings, nil
}

// codeScanningResult holds the result of checking code scanning status.
type codeScanningResult struct {
	enabled          bool
	permissionDenied bool
	errorMessage     string
	// err is why enabled is unknown. A 403 saying the repository's plan
	// lacks code scanning is an answer, not an error.
	err error
}

// checkCodeScanning checks if code scanning is enabled for a repository. The
// default-setup endpoint only reports GitHub's one-click setup, so a repo
// scanning via a CodeQL or third-party workflow (advanced setup) reads as
// not-configured there. When default setup is off and we weren't denied, fall
// back to the analyses surface, which sees both setups.
func (c *Client) checkCodeScanning(ctx context.Context, owner, repo string) codeScanningResult {
	result := c.checkDefaultSetup(ctx, owner, repo)
	if result.enabled || result.permissionDenied || result.err != nil {
		return result
	}
	has, err := c.hasCodeScanningAnalyses(ctx, owner, repo)
	if err != nil {
		result.err = err
		return result
	}
	result.enabled = has
	return result
}

// checkDefaultSetup reports whether GitHub's one-click default code scanning
// setup is configured for the repository. A 404 means default setup is not
// available for the repository, so the caller checks for analyses instead.
func (c *Client) checkDefaultSetup(ctx context.Context, owner, repo string) codeScanningResult {
	path := fmt.Sprintf("/repos/%s/%s/code-scanning/default-setup", owner, repo)
	var result struct {
		State *string `json:"state"`
	}
	err := c.getJSON(ctx, "github.code_scanning_default_setup.get", path, &result)
	var apiErr *APIError
	switch {
	case err == nil && result.State == nil:
		return codeScanningResult{err: invalidResponse("%s response has no state", path)}
	case err == nil:
		return codeScanningResult{enabled: *result.State == StateConfigured}
	case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound:
		return codeScanningResult{}
	case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden && !apiErr.throttled():
		message := apiErr.Message
		if message == "" {
			message = "403 Forbidden"
		}
		denied := codeScanningResult{permissionDenied: true, errorMessage: message}
		if !apiErr.featureOff {
			denied.err = err
		}
		return denied
	default:
		return codeScanningResult{err: err}
	}
}

// hasCodeScanningAnalyses reports whether the repo has at least one code
// scanning analysis, which is how advanced (workflow-based) setup surfaces.
// GitHub answers 404 when a repository has no analyses, and 403 with a
// feature message when its plan lacks code scanning; both mean none.
func (c *Client) hasCodeScanningAnalyses(ctx context.Context, owner, repo string) (bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/code-scanning/analyses?per_page=1", owner, repo)
	var analyses *[]json.RawMessage
	err := c.getJSON(ctx, "github.code_scanning_analyses.list", path, &analyses)
	switch {
	case err == nil && analyses == nil:
		return false, invalidResponse("%s response is not a list", trimQuery(path))
	case err == nil:
		return len(*analyses) > 0, nil
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrFeatureUnavailable):
		return false, nil
	default:
		return false, err
	}
}

// setAPIHeaders sets the standard GitHub API headers on a request.
func setAPIHeaders(req *http.Request) {
	req.Header.Set("Accept", AcceptHeader)
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
}

func trimQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}
