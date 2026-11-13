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
	"sync"

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
	FetchInstallationRepositories(ctx context.Context) (*InstallationRepositories, error)
	FetchSecuritySettings(ctx context.Context, owner, repo string) (*SecuritySettings, error)
	GetBranchRules(ctx context.Context, owner, repo, branch string) ([]BranchRule, error)
	GetRepoRuleset(ctx context.Context, owner, repo string, rulesetID int64) (*Ruleset, error)

	// Audit / internal surfaces.
	GetOrgSettings(ctx context.Context, org string) (*OrgSettings, error)
	ListSecretScanningAlerts(ctx context.Context, owner, repo string) ([]SecretScanningAlert, bool, error)
	ListCodeScanningAlerts(ctx context.Context, owner, repo string) ([]CodeScanningAlert, bool, error)
	ListDependabotAlerts(ctx context.Context, owner, repo string) ([]DependabotAlert, bool, error)
	GetOrgMembership(ctx context.Context, org string) (*OrgMembership, error)
	GetOrgRosters(ctx context.Context, org string) (*OrgMembership, error)
	FetchOrgSSO(ctx context.Context, org string) (*OrgSSO, error)
	GetCodeownersInfo(ctx context.Context, owner, repo string, wantHash bool) (present bool, path string, hash string, err error)
	ListOrgHooks(ctx context.Context, org string) ([]Hook, bool, error)
	ListRepoHooks(ctx context.Context, owner, repo string) ([]Hook, bool, error)
	ListRepoDeployKeys(ctx context.Context, owner, repo string) ([]DeployKey, bool, error)
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
	exchanges    *tokenExchanges
	// installationToken marks a token passed in as one minted for a GitHub App
	// installation.
	installationToken bool
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
		httpClient:        &http.Client{Transport: transport},
		baseURL:           DefaultBaseURL,
		graphqlURL:        DefaultGraphQLURL,
		installationToken: strings.HasPrefix(token, installationTokenPrefix),
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
	exchanges := &tokenExchanges{base: base}
	itr, err := ghinstallation.New(exchanges, appID, installationID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub App transport: %w", err)
	}
	return &Client{
		httpClient:   &http.Client{Transport: itr},
		baseURL:      DefaultBaseURL,
		graphqlURL:   DefaultGraphQLURL,
		installation: itr,
		exchanges:    exchanges,
	}, nil
}

// tokenExchanges sends requests through base and keeps the repository
// selection GitHub returns with each installation token, which ghinstallation
// does not keep.
type tokenExchanges struct {
	base      http.RoundTripper
	mu        sync.Mutex
	selection string
}

func (t *tokenExchanges) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if _, exchange := NameOperation(req); !exchange || err != nil || resp.StatusCode != http.StatusCreated {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var token struct {
		RepositorySelection string `json:"repository_selection"`
	}
	if json.Unmarshal(body, &token) == nil {
		t.mu.Lock()
		t.selection = token.RepositorySelection
		t.mu.Unlock()
	}
	return resp, nil
}

// repositorySelection is the selection the last token exchange reported, or
// "" when it reported none.
func (t *tokenExchanges) repositorySelection() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.selection
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
	return c.doAccept(ctx, op, method, url, body, AcceptHeader)
}

// doAccept is do with accept as the request's media type. An operation with
// no permission gets the one OperationPermissions lists for it.
func (c *Client) doAccept(ctx context.Context, op componentsdk.Operation, method, url string, body []byte, accept string) (*http.Response, error) {
	if op.Permission == "" {
		op.Permission = ReadPermission(op.Name)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx, op), method, url, reader)
	if err != nil {
		return nil, err
	}
	setAPIHeaders(req)
	req.Header.Set("Accept", accept)
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
	_, err := c.getJSONResponse(ctx, op, path, out)
	return err
}

// getJSONResponse is getJSON that also returns the response, so an error
// about what the body holds can name the call with
// componentsdk.ResponseError.
func (c *Client) getJSONResponse(ctx context.Context, op, path string, out any) (*http.Response, error) {
	resp, err := c.do(ctx, componentsdk.Operation{Name: op}, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding response: %w", trimQuery(path), err))
	}
	return resp, nil
}

// graphQL runs a named query and returns its response, so an error about
// what the data holds can name the call. GraphQL queries are reads sent with
// POST, so they are marked safe to retry.
func (c *Client) graphQL(ctx context.Context, op, query string, variables map[string]any, data any) (*http.Response, error) {
	if c.graphqlURL == "" {
		return nil, errors.New("graphql client not configured")
	}
	payload, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, componentsdk.Operation{Name: op, Safe: true}, http.MethodPost, c.graphqlURL, payload)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphQLError  `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("graphql: decoding response: %w", err))
	}
	if len(out.Errors) > 0 {
		return nil, componentsdk.ResponseError(resp, newGraphQLError(resp, out.Errors))
	}
	if len(out.Data) == 0 || string(out.Data) == "null" {
		return nil, componentsdk.ResponseError(resp, invalidResponse("graphql response has no data"))
	}
	if err := json.Unmarshal(out.Data, data); err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("graphql: decoding data: %w", err))
	}
	return resp, nil
}

// FetchRepositories fetches all repositories for an organization with pagination.
// It returns repositories one page at a time via the callback function. A
// node that leaves out a field the query selects, or holds null where
// GitHub's schema does not allow it, makes the answer invalid.
func (c *Client) FetchRepositories(ctx context.Context, org string, callback func([]Repository) error) error {
	var cursor *string
	for {
		var data struct {
			Organization *struct {
				Repositories *struct {
					Nodes    *[]json.RawMessage
					PageInfo *pageInfo
				}
			}
		}
		resp, err := c.graphQL(ctx, "github.repositories.list", repositoriesQuery, map[string]any{"org": org, "cursor": cursor}, &data)
		if err != nil {
			return err
		}
		if data.Organization == nil || data.Organization.Repositories == nil || data.Organization.Repositories.Nodes == nil || data.Organization.Repositories.PageInfo == nil {
			return componentsdk.ResponseError(resp, invalidResponse("graphql repositories response has no repository list or pageInfo"))
		}
		page := data.Organization.Repositories
		repos := make([]Repository, 0, len(*page.Nodes))
		for _, raw := range *page.Nodes {
			if err := checkRepositoryNode(raw); err != nil {
				return componentsdk.ResponseError(resp, err)
			}
			var repo Repository
			if err := json.Unmarshal(raw, &repo); err != nil {
				return componentsdk.ResponseError(resp, fmt.Errorf("graphql: decoding repository: %w", err))
			}
			repos = append(repos, repo)
		}
		if err := callback(repos); err != nil {
			return err
		}
		if !page.PageInfo.HasNextPage {
			return nil
		}
		next := page.PageInfo.EndCursor
		cursor = &next
	}
}

// InstallationRepositories is the GitHub App installation's repository
// access. Names holds the lowercased names of the repositories it is
// installed on, and is nil when Selection is RepositorySelectionAll.
type InstallationRepositories struct {
	Selection string
	Names     map[string]bool
}

// FetchInstallationRepositories reads the repositories the GitHub App's
// installation can read. An installation on all repositories needs no list,
// so the first page that says so ends the read.
func (c *Client) FetchInstallationRepositories(ctx context.Context) (*InstallationRepositories, error) {
	const path = "/installation/repositories?per_page=100"
	out := &InstallationRepositories{Names: map[string]bool{}}
	next := c.baseURL + path
	for next != "" {
		resp, err := c.do(ctx, componentsdk.Operation{Name: "github.installation_repositories.list"}, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			RepositorySelection string `json:"repository_selection"`
			TotalCount          *int   `json:"total_count"`
			Repositories        *[]struct {
				Name string `json:"name"`
			} `json:"repositories"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&page)
		link := resp.Header.Get("Link")
		_ = resp.Body.Close()
		switch {
		case decErr != nil:
			return nil, componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding response: %w", trimQuery(path), decErr))
		case page.RepositorySelection == RepositorySelectionAll:
			return &InstallationRepositories{Selection: RepositorySelectionAll}, nil
		case page.RepositorySelection != RepositorySelectionSelected:
			return nil, componentsdk.ResponseError(resp, invalidResponse("%s response has no repository_selection", trimQuery(path)))
		case page.Repositories == nil || page.TotalCount == nil:
			return nil, componentsdk.ResponseError(resp, invalidResponse("%s response has no repositories list or total_count", trimQuery(path)))
		case len(*page.Repositories) == 0 && len(out.Names) < *page.TotalCount:
			return nil, componentsdk.ResponseError(resp, emptyPage(trimQuery(path), "repositories", *page.TotalCount))
		}
		out.Selection = RepositorySelectionSelected
		for _, r := range *page.Repositories {
			if r.Name == "" {
				return nil, componentsdk.ResponseError(resp, invalidResponse("%s response lists a repository with no name", trimQuery(path)))
			}
			out.Names[strings.ToLower(r.Name)] = true
		}
		next = ""
		if m := linkNextRe.FindStringSubmatch(link); m != nil {
			next = m[1]
		}
	}
	return out, nil
}

// OrgSecurity represents organization-level security settings and the
// credential that read them. TwoFactorRequired is nil when GitHub left the
// setting out, which it does unless the caller is an organization owner.
// RepositoryCount is GitHub's count of the organization's repositories,
// archived ones included: public_repos plus owned_private_repos, which counts
// internal repositories too, unlike total_private_repos. It is nil when GitHub
// left owned_private_repos out, which it also does unless the caller is an
// organization owner.
type OrgSecurity struct {
	// Login is the organization's login, in the case GitHub returns it.
	Login             string
	TwoFactorRequired *bool
	RepositoryCount   *int
	Credential        Credential

	// DefaultRepositoryPermission is the members' base permission on every
	// repository, empty when GitHub withholds it.
	DefaultRepositoryPermission string
}

// Credential kinds. For CredentialAppInstallation, the collector exchanges the
// App's key for tokens. CredentialInstallationToken is an installation token
// minted elsewhere, and CredentialToken is any other token passed in.
const (
	CredentialAppInstallation   = "app_installation"
	CredentialInstallationToken = "installation_token"
	CredentialToken             = "token"
)

// Repository selections of a GitHub App installation.
const (
	RepositorySelectionAll      = "all"
	RepositorySelectionSelected = "selected"
)

// Credential describes what the collector signed in as.
type Credential struct {
	// Kind is one of the credential kinds above.
	Kind string
	// ID is the GitHub App's ID. Tokens have none.
	ID string
	// Scopes are the installation's permissions, as name:level, or a classic
	// token's OAuth scopes.
	Scopes []string
	// RepositorySelection is the installation's repository access as the
	// token exchange reported it, or "" for a token or an exchange that
	// reported none.
	RepositorySelection string
}

// Installation reports whether the credential signs in as a GitHub App
// installation, which can read only the repositories in its selection.
func (c Credential) Installation() bool {
	return c.Kind == CredentialAppInstallation || c.Kind == CredentialInstallationToken
}

// FetchOrgSecurity signs in and reads organization-level security settings.
// For a GitHub App it first exchanges the App's key for an installation
// token. Any failure is returned, since nothing else can be read without it.
// A 404 on the organization means it does not exist, so that failure is
// config_invalid.
//
// The two-factor requirement comes from the REST API. A GitHub App gets a
// FORBIDDEN error for GraphQL's requiresTwoFactorAuthentication even with the
// organization Administration permission:
// https://github.com/orgs/community/discussions/45063
// FetchOrgSSO reads SAML single sign-on, which needs the members permission.
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
			Kind:                CredentialAppInstallation,
			ID:                  strconv.FormatInt(c.installation.AppID(), 10),
			Scopes:              installationScopes(c.installation),
			RepositorySelection: c.exchanges.repositorySelection(),
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
		DefaultRepositoryPermission string `json:"default_repository_permission"`
		PublicRepos                 *int   `json:"public_repos"`
		OwnedPrivateRepos           *int   `json:"owned_private_repos"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("%s: decoding response: %w", path, err)
	}
	if body.Login == "" {
		return nil, invalidResponse("%s response has no login", path)
	}
	result.Login = body.Login
	result.TwoFactorRequired = body.TwoFactorRequirementEnabled
	result.DefaultRepositoryPermission = body.DefaultRepositoryPermission
	if body.PublicRepos != nil && body.OwnedPrivateRepos != nil {
		count := *body.PublicRepos + *body.OwnedPrivateRepos
		result.RepositoryCount = &count
	}
	if c.installation == nil {
		result.Credential = Credential{Kind: CredentialToken, Scopes: splitScopes(resp.Header.Get("X-OAuth-Scopes"))}
		if c.installationToken {
			result.Credential.Kind = CredentialInstallationToken
		}
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
	// rights. Nil means they hold GitHub's answer, unless the setting's own
	// error below says why GitHub's block has none for it.
	AnalysisErr                     error
	SecretScanningErr               error
	SecretScanningPushProtectionErr error
	DependabotSecurityUpdatesErr    error

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
		Name                string                    `json:"name"`
		SecurityAndAnalysis map[string]*securityState `json:"security_and_analysis"`
	}
	resp, err := c.getJSONResponse(ctx, "github.repos.get", path, &result)
	if err != nil {
		return nil, fmt.Errorf("security settings for %s/%s: %w", owner, repo, err)
	}
	if result.Name == "" {
		return nil, componentsdk.ResponseError(resp, invalidResponse("%s response has no name", path))
	}

	settings := &SecuritySettings{}
	if sa := result.SecurityAndAnalysis; sa != nil {
		// GitHub's schema makes each setting in the block optional, so one
		// it leaves out is unknown rather than disabled.
		status := func(name string) (bool, error) {
			state := sa[name]
			if state == nil || state.Status == nil {
				return false, componentsdk.ResponseError(resp, invalidResponse("%s response's security_and_analysis has no %s status", path, name))
			}
			return *state.Status == StatusEnabled, nil
		}
		settings.SecretScanning, settings.SecretScanningErr = status("secret_scanning")
		settings.SecretScanningPushProtection, settings.SecretScanningPushProtectionErr = status("secret_scanning_push_protection")
		settings.DependabotSecurityUpdates, settings.DependabotSecurityUpdatesErr = status("dependabot_security_updates")
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

// securityState is one setting of a repository's security_and_analysis.
type securityState struct {
	Status *string `json:"status"`
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
	resp, err := c.getJSONResponse(ctx, "github.code_scanning_default_setup.get", path, &result)
	var apiErr *APIError
	switch {
	case err == nil && result.State == nil:
		return codeScanningResult{err: componentsdk.ResponseError(resp, invalidResponse("%s response has no state", path))}
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
