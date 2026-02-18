package collector

import "github.com/locktivity/epack-collector-github/internal/github"

// repoInfo holds repository identification for API calls.
type repoInfo struct {
	owner string
	name  string
}

// metricsAggregator collects repository metrics during iteration.
type metricsAggregator struct {
	// Scope tracking
	totalRepos    int
	excludedRepos int
	repos         []repoInfo

	// Branch protection counts
	branchProtectionEnabled int
	requirePullRequest      int
	requireApprovingReviews int
	dismissStaleReviews     int
	requireCodeOwnerReviews int
	requireStatusChecks     int
	requireSignedCommits    int
	enforceAdmins           int

	// Security feature counts
	vulnerabilityAlertsEnabled       int
	codeScanningEnabled              int
	secretScanningEnabled            int
	secretScanningPushProtection     int
	dependabotSecurityUpdatesEnabled int
}

// processRepository processes a single repository and updates metrics.
func (m *metricsAggregator) processRepository(repo github.Repository, includePatterns, excludePatterns []string) {
	if !ShouldIncludeRepo(repo.Name, includePatterns, excludePatterns) {
		m.excludedRepos++
		return
	}

	m.totalRepos++
	m.repos = append(m.repos, repoInfo{owner: repo.Owner.Login, name: repo.Name})

	m.countBranchProtection(repo)

	if repo.HasVulnerabilityAlertsEnabled {
		m.vulnerabilityAlertsEnabled++
	}
}

// countBranchProtection counts branch protection features for a repository.
func (m *metricsAggregator) countBranchProtection(repo github.Repository) {
	bp := repo.DefaultBranchRef.BranchProtectionRule
	if bp == nil {
		return
	}

	m.branchProtectionEnabled++

	if bp.RequiresApprovingReviews {
		m.requirePullRequest++
		m.requireApprovingReviews++
	}
	if bp.DismissesStaleReviews {
		m.dismissStaleReviews++
	}
	if bp.RequiresCodeOwnerReviews {
		m.requireCodeOwnerReviews++
	}
	if bp.RequiresStatusChecks {
		m.requireStatusChecks++
	}
	if bp.RequiresCommitSignatures {
		m.requireSignedCommits++
	}
	if bp.IsAdminEnforced {
		m.enforceAdmins++
	}
}

// countSecuritySettings updates security feature counts from REST API settings.
func (m *metricsAggregator) countSecuritySettings(settings *github.SecuritySettings) {
	if settings.CodeScanningEnabled {
		m.codeScanningEnabled++
	}
	if settings.SecretScanning {
		m.secretScanningEnabled++
	}
	if settings.SecretScanningPushProtection {
		m.secretScanningPushProtection++
	}
	if settings.DependabotSecurityUpdates {
		m.dependabotSecurityUpdatesEnabled++
	}
}

// securityFeaturesCoverage calculates the average coverage across all security features.
func (m *metricsAggregator) securityFeaturesCoverage() int {
	if m.totalRepos == 0 {
		return 0
	}
	total := m.vulnerabilityAlertsEnabled + m.codeScanningEnabled +
		m.secretScanningEnabled + m.secretScanningPushProtection +
		m.dependabotSecurityUpdatesEnabled
	return (total * MaxPercentage) / (m.totalRepos * NumSecurityFeatures)
}

// toBranchProtectionRules converts counts to percentages.
func (m *metricsAggregator) toBranchProtectionRules() BranchProtectionRules {
	return BranchProtectionRules{
		PullRequestRequired: percent(m.requirePullRequest, m.totalRepos),
		ApprovingReviews:    percent(m.requireApprovingReviews, m.totalRepos),
		DismissStaleReviews: percent(m.dismissStaleReviews, m.totalRepos),
		CodeOwnerReviews:    percent(m.requireCodeOwnerReviews, m.totalRepos),
		StatusChecks:        percent(m.requireStatusChecks, m.totalRepos),
		SignedCommits:       percent(m.requireSignedCommits, m.totalRepos),
		AdminEnforcement:    percent(m.enforceAdmins, m.totalRepos),
	}
}

// toSecurityFeatures converts counts to percentages.
func (m *metricsAggregator) toSecurityFeatures() SecurityFeatures {
	return SecurityFeatures{
		VulnerabilityAlerts:          percent(m.vulnerabilityAlertsEnabled, m.totalRepos),
		CodeScanning:                 percent(m.codeScanningEnabled, m.totalRepos),
		SecretScanning:               percent(m.secretScanningEnabled, m.totalRepos),
		SecretScanningPushProtection: percent(m.secretScanningPushProtection, m.totalRepos),
		DependabotSecurityUpdates:    percent(m.dependabotSecurityUpdatesEnabled, m.totalRepos),
	}
}
