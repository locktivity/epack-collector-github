package collector

import (
	"context"
	"errors"
	"fmt"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// Collector collects GitHub organization security posture.
type Collector struct {
	client github.GitHubClient
	config Config
}

// status reports an indeterminate status update.
func (c *Collector) status(message string) {
	if c.config.OnStatus != nil {
		c.config.OnStatus(message)
	}
}

// progress reports a determinate progress update.
func (c *Collector) progress(current, total int64, message string) {
	if c.config.OnProgress != nil {
		c.config.OnProgress(current, total, message)
	}
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
//
// level controls collection depth: trust emits org-level aggregates only;
// audit adds per-repo configs and member/repo inventories; internal adds
// per-user activity, findings inventories, and the audit-log slice. Levels are
// cumulative.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	if c.config.Organization == "" {
		return nil, fmt.Errorf("organization is required")
	}

	includePatterns := c.config.IncludePatterns
	if len(includePatterns) == 0 {
		includePatterns = []string{DefaultIncludePattern}
	}

	posture := NewOrgPosture(c.config.Organization)
	posture.CollectedAtLevel = string(level)

	metrics := &metricsAggregator{}

	c.status(fmt.Sprintf("Connecting to GitHub org %s...", c.config.Organization))

	// Core surfaces degrade rather than fail the whole run: a permission gap or
	// transient error on org security or the repo list records a diagnostic and
	// the collector emits whatever else it can.
	orgSecurity, err := c.client.FetchOrgSecurity(ctx, c.config.Organization)
	if err != nil {
		c.degradeCore(metrics, "organization_security", "organization administration: read", err)
		orgSecurity = &github.OrgSecurity{}
	}

	c.status("Fetching repositories...")

	repoCount := 0
	err = c.client.FetchRepositories(ctx, c.config.Organization, func(repos []github.Repository) error {
		for _, repo := range repos {
			metrics.processRepository(repo, includePatterns, c.config.ExcludePatterns)
		}
		repoCount += len(repos)
		c.status(fmt.Sprintf("Found %d repositories...", repoCount))
		return nil
	})
	if err != nil {
		c.degradeCore(metrics, "repositories", "metadata: read", err)
	}

	c.fetchSecuritySettings(ctx, metrics)

	c.populatePosture(posture, orgSecurity, metrics, includePatterns)

	c.collectSurfaces(ctx, posture, metrics, level)

	// Diagnostics are assembled last so surface-collector permission errors and
	// feature-unavailable warnings are included alongside the core ones.
	posture.Diagnostics = metrics.toDiagnostics()

	c.status("Collection complete")

	return posture, nil
}

// degradeCore records a diagnostic for a failed core-surface fetch instead of
// failing the run. A permission denial names the missing permission; any other
// error becomes an informational warning. The caller proceeds with zeroed data.
func (c *Collector) degradeCore(metrics *metricsAggregator, surface, missingPerm string, err error) {
	if errors.Is(err, github.ErrPermissionDenied) {
		metrics.diag.surfacePermissionDenied(surface, missingPerm)
		return
	}
	metrics.diag.surfaceUnavailable(surface, fmt.Sprintf("fetch failed: %v", err))
}

// collectionPass carries the shared state for one audit/internal surface pass.
type collectionPass struct {
	ctx     context.Context
	posture *OrgPosture
	metrics *metricsAggregator
	level   componentsdk.Level
	org     string
}

// internal reports whether the pass is collecting at internal level.
func (p *collectionPass) internal() bool {
	return p.level.AtLeast(componentsdk.LevelInternal)
}

// isDenied reports whether err is (or wraps) a permission denial.
func isDenied(err error) bool {
	return err != nil && errors.Is(err, github.ErrPermissionDenied)
}

// isFeatureUnavailable reports whether err signals a missing org feature
// (e.g. Enterprise-only audit log, fine-grained-token policy).
func isFeatureUnavailable(err error) bool {
	return err != nil && errors.Is(err, github.ErrFeatureUnavailable)
}

// collectSurfaces runs the audit- and internal-gated surface collectors. At
// trust it is a no-op, so trust output is unchanged. augment* methods extend
// structs that already exist at trust (access control, security features);
// collect* methods populate the audit/internal-only surfaces.
func (c *Collector) collectSurfaces(ctx context.Context, posture *OrgPosture, metrics *metricsAggregator, level componentsdk.Level) {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return
	}

	p := &collectionPass{
		ctx:     ctx,
		posture: posture,
		metrics: metrics,
		level:   level,
		org:     c.config.Organization,
	}

	c.augmentAccessControl(p)
	c.augmentSecurityFeatures(p)
	c.collectRepositories(p)
	c.collectCodeowners(p)
	c.collectWebhooks(p)
	c.collectDeployKeys(p)
	c.collectActions(p)
	// Per-member last-activity comes from the audit log, so it runs before the
	// member inventory and feeds it the actor→last-activity map.
	activity := c.collectAuditLog(p)
	c.collectApps(p)
	c.collectTokens(p)
	c.collectMembers(p, activity)
}

// augmentAccessControl adds audit-level org access-control fields (default repo
// permission, members-can-create-repositories) from GET /orgs/{org}. On a
// permission denial the fields stay zero/nil and a diagnostic is recorded.
func (c *Collector) augmentAccessControl(p *collectionPass) {
	settings, err := c.client.GetOrgSettings(p.ctx, p.org)
	if err != nil {
		if isDenied(err) {
			p.metrics.diag.surfacePermissionDenied("access_control", "organization_administration:read")
		}
		return
	}
	p.posture.AccessControl.DefaultRepositoryPermission = settings.DefaultRepositoryPermission
	p.posture.AccessControl.MembersCanCreateRepositories = settings.MembersCanCreateRepositories
}

// fetchSecuritySettings fetches REST API security settings for all repositories.
func (c *Collector) fetchSecuritySettings(ctx context.Context, metrics *metricsAggregator) {
	total := int64(len(metrics.repos.included))
	for i, repo := range metrics.repos.included {
		owner, name := repo.Owner.Login, repo.Name
		c.progress(int64(i+1), total, fmt.Sprintf("Checking security settings for %s", name))
		settings, err := c.client.FetchSecuritySettings(ctx, owner, name)
		if err != nil {
			if errors.Is(err, github.ErrPermissionDenied) {
				metrics.trackSecuritySettingsPermissionDenied()
			}
			continue
		}
		metrics.countSecuritySettings(settings)
		metrics.repos.recordSettings(owner, name, settings)
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
