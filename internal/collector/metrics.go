package collector

import (
	"fmt"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// metricsAggregator collects repository metrics during iteration.
type metricsAggregator struct {
	// Scope tracking
	totalRepos    int
	excludedRepos int

	// repos holds the included repositories and their REST security settings,
	// captured for the audit/internal surface pass.
	repos repoCache

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

	// Permission error tracking
	securitySettingsPermissionDenied int
	codeScanningPermissionDenied     int
	codeScanningErrorMessages        map[string]int // Track unique error messages and their counts

	// diag accumulates surface-level permission errors and feature-unavailable
	// warnings recorded during the surface pass.
	diag diagnostics
}

// processRepository processes a single repository and updates metrics.
func (m *metricsAggregator) processRepository(repo github.Repository, includePatterns, excludePatterns []string) {
	if repo.IsArchived {
		m.excludedRepos++
		return
	}

	if !ShouldIncludeRepo(repo.Name, includePatterns, excludePatterns) {
		m.excludedRepos++
		return
	}

	m.totalRepos++
	m.repos.add(repo)

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
	if settings.CodeScanningPermissionDenied {
		m.codeScanningPermissionDenied++
		m.trackCodeScanningError(settings.CodeScanningErrorMessage)
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

// trackSecuritySettingsPermissionDenied increments the permission denied counter.
func (m *metricsAggregator) trackSecuritySettingsPermissionDenied() {
	m.securitySettingsPermissionDenied++
}

// trackCodeScanningError records a code scanning error message.
func (m *metricsAggregator) trackCodeScanningError(msg string) {
	if msg == "" {
		return
	}
	if m.codeScanningErrorMessages == nil {
		m.codeScanningErrorMessages = make(map[string]int)
	}
	m.codeScanningErrorMessages[msg]++
}

// codeScanningErrors returns diagnostic error messages for code scanning 403s.
func (m *metricsAggregator) codeScanningErrors() []string {
	if m.codeScanningPermissionDenied == 0 {
		return nil
	}
	if len(m.codeScanningErrorMessages) == 0 {
		return []string{fmt.Sprintf("code scanning 403 on %d/%d repos (unknown reason)", m.codeScanningPermissionDenied, m.totalRepos)}
	}
	var errors []string
	for msg, count := range m.codeScanningErrorMessages {
		errors = append(errors, fmt.Sprintf("code scanning 403 on %d/%d repos: %s", count, m.totalRepos, msg))
	}
	return errors
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

// toDiagnostics combines the trust-pass permission counters (security settings,
// code scanning) with the accumulated surface diagnostics. Trust-pass errors
// come first to preserve their original ordering. Returns nil if there's
// nothing to report.
func (m *metricsAggregator) toDiagnostics() *Diagnostics {
	out := &diagnostics{}

	if m.securitySettingsPermissionDenied > 0 {
		out.addPermissionError(fmt.Sprintf(
			"security_events permission required: got 403 on %d/%d repos when fetching security settings (secret scanning, dependabot)",
			m.securitySettingsPermissionDenied, m.totalRepos,
		))
	}
	for _, e := range m.codeScanningErrors() {
		out.addPermissionError(e)
	}

	out.permissionErrors = append(out.permissionErrors, m.diag.permissionErrors...)
	out.warnings = append(out.warnings, m.diag.warnings...)

	return out.build()
}
