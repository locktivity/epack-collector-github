package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// Collector collects GitHub organization security posture.
type Collector struct {
	client github.GitHubClient
	config Config
}

// New creates a new Collector with the given configuration.
// It supports two authentication methods:
//   - GitHub App (recommended): Set AppID, InstallationID, and PrivateKey
//   - Classic PAT (legacy): Set GitHubToken
func New(config Config) (*Collector, error) {
	var client github.GitHubClient
	var err error

	if config.AppID != 0 && config.PrivateKey != "" {
		// GitHub App auth (recommended)
		if config.InstallationID == 0 {
			return nil, fmt.Errorf("installation_id is required when using GitHub App authentication")
		}
		client, err = github.NewClientFromApp(
			config.AppID,
			config.InstallationID,
			[]byte(config.PrivateKey),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub App client: %w", err)
		}
	} else if config.GitHubToken != "" {
		// Classic PAT auth (legacy)
		client = github.NewClient(config.GitHubToken)
	} else {
		return nil, fmt.Errorf("authentication required: provide app_id + private_key (recommended) or github_token")
	}

	return &Collector{
		client: client,
		config: config,
	}, nil
}

// NewWithClient creates a Collector with a custom client (for testing).
func NewWithClient(config Config, client github.GitHubClient) *Collector {
	return &Collector{
		client: client,
		config: config,
	}
}

// Collect fetches and aggregates security posture metrics for the organization.
func (c *Collector) Collect(ctx context.Context) (*OrgPosture, error) {
	if c.config.Organization == "" {
		return nil, fmt.Errorf("organization is required")
	}

	includePatterns := c.config.IncludePatterns
	if len(includePatterns) == 0 {
		includePatterns = []string{DefaultIncludePattern}
	}

	posture := NewOrgPosture(c.config.Organization)

	orgSecurity, err := c.client.FetchOrgSecurity(ctx, c.config.Organization)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch org security: %w", err)
	}

	metrics := &metricsAggregator{}

	err = c.client.FetchRepositories(ctx, c.config.Organization, func(repos []github.Repository) error {
		for _, repo := range repos {
			metrics.processRepository(repo, includePatterns, c.config.ExcludePatterns)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repositories: %w", err)
	}

	c.fetchSecuritySettings(ctx, metrics)

	c.populatePosture(posture, orgSecurity, metrics, includePatterns)

	return posture, nil
}

// fetchSecuritySettings fetches REST API security settings for all repositories.
func (c *Collector) fetchSecuritySettings(ctx context.Context, metrics *metricsAggregator) {
	for _, repo := range metrics.repos {
		settings, err := c.client.FetchSecuritySettings(ctx, repo.owner, repo.name)
		if err != nil {
			continue
		}
		metrics.countSecuritySettings(settings)
	}
}

// populatePosture fills in the posture struct from collected metrics.
func (c *Collector) populatePosture(posture *OrgPosture, orgSecurity *github.OrgSecurity, metrics *metricsAggregator, includePatterns []string) {
	excludePatterns := c.config.ExcludePatterns
	if excludePatterns == nil {
		excludePatterns = []string{}
	}

	totalOrgRepos := metrics.totalRepos + metrics.excludedRepos

	posture.Scope = Scope{
		IncludePatterns:      includePatterns,
		ExcludePatterns:      excludePatterns,
		RepositoriesCoverage: percent(metrics.totalRepos, totalOrgRepos),
	}

	posture.Posture = Posture{
		BranchProtectionCoverage: percent(metrics.branchProtectionEnabled, metrics.totalRepos),
		SecurityFeaturesCoverage: metrics.securityFeaturesCoverage(),
	}

	posture.AccessControl = AccessControl{
		TwoFactorRequired: orgSecurity.TwoFactorRequired,
	}

	posture.BranchProtectionRules = metrics.toBranchProtectionRules()
	posture.SecurityFeatures = metrics.toSecurityFeatures()
}

// percent calculates the percentage of count over total, returning 0 if total is 0.
func percent(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count * MaxPercentage) / total
}
