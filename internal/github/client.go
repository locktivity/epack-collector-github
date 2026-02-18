package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// GitHubClient defines the interface for GitHub API operations.
// This interface allows for easy mocking in tests.
type GitHubClient interface {
	FetchOrgSecurity(ctx context.Context, org string) (*OrgSecurity, error)
	FetchRepositories(ctx context.Context, org string, callback func([]Repository) error) error
	FetchSecuritySettings(ctx context.Context, owner, repo string) (*SecuritySettings, error)
}

// Client wraps the GitHub GraphQL and REST clients.
type Client struct {
	graphql    *githubv4.Client
	httpClient *http.Client
	token      string
	baseURL    string // REST API base URL (for testing with httptest)
}

// Ensure Client implements GitHubClient.
var _ GitHubClient = (*Client)(nil)

// NewClient creates a new GitHub client with the given token.
func NewClient(token string) *Client {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	httpClient := oauth2.NewClient(context.Background(), src)

	return &Client{
		graphql:    githubv4.NewClient(httpClient),
		httpClient: httpClient,
		token:      token,
		baseURL:    DefaultBaseURL,
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
		graphql:    githubv4.NewEnterpriseClient(graphqlURL, httpClient),
		httpClient: httpClient,
		baseURL:    baseURL,
	}
}

// NewClientFromApp creates a client using GitHub App authentication.
// This is the recommended authentication method for organization-level access.
func NewClientFromApp(appID, installationID int64, privateKey []byte) (*Client, error) {
	itr, err := ghinstallation.New(http.DefaultTransport, appID, installationID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub App transport: %w", err)
	}

	httpClient := &http.Client{Transport: itr}
	return &Client{
		graphql:    githubv4.NewClient(httpClient),
		httpClient: httpClient,
		baseURL:    DefaultBaseURL,
	}, nil
}

// FetchRepositories fetches all repositories for an organization with pagination.
// It returns repositories one page at a time via the callback function.
func (c *Client) FetchRepositories(ctx context.Context, org string, callback func([]Repository) error) error {
	var cursor *githubv4.String

	for {
		var query RepositoriesQuery
		variables := map[string]interface{}{
			"org":    githubv4.String(org),
			"cursor": cursor,
		}

		if err := c.graphql.Query(ctx, &query, variables); err != nil {
			return err
		}

		if err := callback(query.Organization.Repositories.Nodes); err != nil {
			return err
		}

		if !query.Organization.Repositories.PageInfo.HasNextPage {
			break
		}

		cursor = &query.Organization.Repositories.PageInfo.EndCursor
	}

	return nil
}

// OrgSecurity represents organization-level security settings.
// TwoFactorRequired is a pointer to indicate when we couldn't
// determine the value (nil = insufficient permissions).
type OrgSecurity struct {
	TwoFactorRequired *bool
}

// FetchOrgSecurity fetches organization-level security settings.
// Uses REST API for 2FA detection. SSO status is not checked due to GitHub API limitations.
// If insufficient permissions, fields will be nil (unknown).
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

	// Fetch 2FA via REST API (works with GitHub Apps, unlike GraphQL)
	twoFA, err := c.fetchOrgTwoFactorREST(ctx, org)
	if err == nil {
		result.TwoFactorRequired = twoFA
	}
	// If REST fails, 2FA stays nil (unknown)

	// SSO detection is not supported - always returns nil
	// See comment above for details on the API limitations.

	return result, nil
}

// fetchOrgTwoFactorREST fetches 2FA requirement via REST API.
// This works with GitHub Apps (unlike the GraphQL requiresTwoFactorAuthentication field).
func (c *Client) fetchOrgTwoFactorREST(ctx context.Context, org string) (*bool, error) {
	url := fmt.Sprintf("%s/orgs/%s", c.baseURL, org)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	setAPIHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("org API returned status %d", resp.StatusCode)
	}

	var result struct {
		TwoFactorRequirementEnabled *bool `json:"two_factor_requirement_enabled"`
		// Note: This field is only present for org owners/admins
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.TwoFactorRequirementEnabled, nil
}

// SecuritySettings represents the security settings for a repository.
type SecuritySettings struct {
	SecretScanning               bool
	SecretScanningPushProtection bool
	DependabotSecurityUpdates    bool
	CodeScanningEnabled          bool
}

// FetchSecuritySettings fetches security settings for a repository via REST API.
func (c *Client) FetchSecuritySettings(ctx context.Context, owner, repo string) (*SecuritySettings, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	setAPIHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Return empty settings on error (might not have access)
		return &SecuritySettings{}, nil
	}

	var result struct {
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

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &SecuritySettings{}, nil
	}

	settings := &SecuritySettings{}
	if result.SecurityAndAnalysis != nil {
		if result.SecurityAndAnalysis.SecretScanning != nil {
			settings.SecretScanning = result.SecurityAndAnalysis.SecretScanning.Status == StatusEnabled
		}
		if result.SecurityAndAnalysis.SecretScanningPushProtection != nil {
			settings.SecretScanningPushProtection = result.SecurityAndAnalysis.SecretScanningPushProtection.Status == StatusEnabled
		}
		if result.SecurityAndAnalysis.DependabotSecurityUpdates != nil {
			settings.DependabotSecurityUpdates = result.SecurityAndAnalysis.DependabotSecurityUpdates.Status == StatusEnabled
		}
	}

	// Check code scanning status
	settings.CodeScanningEnabled = c.checkCodeScanning(ctx, owner, repo)

	return settings, nil
}

// checkCodeScanning checks if code scanning is enabled for a repository.
func (c *Client) checkCodeScanning(ctx context.Context, owner, repo string) bool {
	url := fmt.Sprintf("%s/repos/%s/%s/code-scanning/default-setup", c.baseURL, owner, repo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	setAPIHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var result struct {
		State string `json:"state"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	return result.State == StateConfigured
}

// setAPIHeaders sets the standard GitHub API headers on a request.
func setAPIHeaders(req *http.Request) {
	req.Header.Set("Accept", AcceptHeader)
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
}
