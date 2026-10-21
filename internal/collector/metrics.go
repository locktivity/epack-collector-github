package collector

import (
	"errors"
	"fmt"
	"sort"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// metricsAggregator collects repository metrics during iteration.
type metricsAggregator struct {
	// Scope tracking. reposErr is why the repository list could not be read,
	// which leaves every repository-derived value unknown.
	totalRepos    int
	excludedRepos int
	reposErr      error

	// repos holds the included repositories and their REST security settings,
	// captured for the audit/internal surface pass.
	repos repoCache

	// Ruleset read failures on default branches, and the ruleset details read
	// once per ruleset ID (nil for a ruleset that could not be read).
	branchRulesDenied int
	branchRulesFailed int
	rulesetDetails    map[int64]*github.Ruleset

	// Why each repo's default-branch rules or each ruleset could not be read.
	branchRulesErrs map[string]error // keyed by "owner/repo"
	rulesetErrs     map[int64]error

	// Permission error tracking
	securitySettingsPermissionDenied int
	codeScanningPermissionDenied     int
	codeScanningErrorMessages        map[string]int // Track unique error messages and their counts

	// Security settings reads that failed for reasons other than a 403, or
	// that GitHub answered without the settings or code scanning status.
	securitySettingsFailed int
	analysisHidden         int
	codeScanningFailed     int

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
}

// trackBranchRulesError records a failed read of a repo's default-branch rules.
func (m *metricsAggregator) trackBranchRulesError(err error) {
	if isDenied(err) {
		m.branchRulesDenied++
		return
	}
	m.branchRulesFailed++
}

// countSecuritySettings tracks the diagnostics a repo's REST settings call for.
func (m *metricsAggregator) countSecuritySettings(settings *github.SecuritySettings) {
	if settings.CodeScanningPermissionDenied {
		m.codeScanningPermissionDenied++
		m.trackCodeScanningError(settings.CodeScanningErrorMessage)
	} else if settings.CodeScanningErr != nil {
		m.codeScanningFailed++
	}
	if settings.AnalysisErr != nil {
		m.analysisHidden++
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
	var errs []string
	for msg, count := range m.codeScanningErrorMessages {
		errs = append(errs, fmt.Sprintf("code scanning 403 on %d/%d repos: %s", count, m.totalRepos, msg))
	}
	sort.Strings(errs)
	return errs
}

// Security features, in the order the artifact lists them.
type feature int

const (
	featureVulnerabilityAlerts feature = iota
	featureCodeScanning
	featureSecretScanning
	featureSecretScanningPushProtection
	featureDependabotSecurityUpdates
)

var features = []feature{
	featureVulnerabilityAlerts,
	featureCodeScanning,
	featureSecretScanning,
	featureSecretScanningPushProtection,
	featureDependabotSecurityUpdates,
}

// field is the feature's name in the artifact.
func (f feature) field() string {
	return [...]string{
		"vulnerability_alerts",
		"code_scanning",
		"secret_scanning",
		"secret_scanning_push_protection",
		"dependabot_security_updates",
	}[f]
}

// pointer is the feature's percentage in the detailed artifact, and
// countPointer the count of repositories it is taken of.
func (f feature) pointer() string      { return "/security_features/" + f.field() }
func (f feature) countPointer() string { return "/security_features/repository_counts/" + f.field() }

var errSettingsNotRead = errors.New("security settings were not read")

// featureValue returns one repository's value for a security feature, or the
// error that left it unknown.
func (m *metricsAggregator) featureValue(repo github.Repository, f feature) (*bool, error) {
	if f == featureVulnerabilityAlerts {
		return ptr(repo.HasVulnerabilityAlertsEnabled), nil
	}
	owner, name := repo.Owner.Login, repo.Name
	if err := m.repos.settingsErr[owner+"/"+name]; err != nil {
		return nil, err
	}
	s := m.repos.settingsFor(owner, name)
	if s == nil {
		return nil, errSettingsNotRead
	}
	if f == featureCodeScanning {
		if s.CodeScanningErr != nil {
			return nil, s.CodeScanningErr
		}
		return ptr(s.CodeScanningEnabled), nil
	}
	if s.AnalysisErr != nil {
		return nil, s.AnalysisErr
	}
	switch f {
	case featureSecretScanning:
		return ptr(s.SecretScanning), nil
	case featureSecretScanningPushProtection:
		return ptr(s.SecretScanningPushProtection), nil
	default:
		return ptr(s.DependabotSecurityUpdates), nil
	}
}

// rollup is a percentage over the in-scope repositories and the count of
// repositories it takes. Both are nil when some repositories' values are
// unknown, in which case unknown counts them and err is one of the reasons.
// The percentage is also nil when no repository is in scope.
type rollup struct {
	pct     *int
	count   *int
	unknown int
	err     error
}

// featureRollup is the percentage and count of repositories with feature f
// enabled.
func (m *metricsAggregator) featureRollup(f feature) rollup {
	repos := m.repos.included
	var r rollup
	enabled := 0
	for _, repo := range repos {
		v, err := m.featureValue(repo, f)
		switch {
		case v == nil:
			r.unknown++
			if r.err == nil {
				r.err = err
			}
		case *v:
			enabled++
		}
	}
	if r.unknown == 0 {
		r.count = ptr(enabled)
		r.pct = percentOf(r.count, len(repos))
	}
	return r
}

// securityFeaturesCoverage is the average coverage across all security
// features, unknown when any feature of any repository is.
func (m *metricsAggregator) securityFeaturesCoverage() rollup {
	repos := m.repos.included
	if len(repos) == 0 {
		return rollup{}
	}
	var r rollup
	enabled := 0
	for _, repo := range repos {
		repoUnknown := false
		for _, f := range features {
			v, err := m.featureValue(repo, f)
			switch {
			case v == nil:
				repoUnknown = true
				if r.err == nil {
					r.err = err
				}
			case *v:
				enabled++
			}
		}
		if repoUnknown {
			r.unknown++
		}
	}
	if r.unknown == 0 {
		r.pct = ptr((enabled * MaxPercentage) / (len(repos) * NumSecurityFeatures))
	}
	return r
}

// protectedRepositoryCount is the number of repos whose default branch has
// effective protection.
func (m *metricsAggregator) protectedRepositoryCount() *int {
	return rollupCount(m.repos.protectionList(), (*repoProtection).protected)
}

// toBranchProtectionRules rolls each repo's effective protection up to
// per-rule counts and percentages.
func (m *metricsAggregator) toBranchProtectionRules() BranchProtectionRules {
	protections := m.repos.protectionList()
	rule := func(name string) *int {
		return rollupCount(protections, func(p *repoProtection) *bool { return p.state(name) })
	}
	counts := BranchProtectionRuleCounts{
		PullRequestRequired: rule(rulePullRequestRequired),
		ApprovingReviews:    rule(ruleApprovingReviews),
		DismissStaleReviews: rule(ruleDismissStaleReviews),
		CodeOwnerReviews:    rule(ruleCodeOwnerReviews),
		StatusChecks:        rule(ruleStatusChecks),
		SignedCommits:       rule(ruleSignedCommits),
		AdminEnforcement:    rollupCount(protections, func(p *repoProtection) *bool { return p.admin }),
		ForcePushesBlocked:  rule(ruleForcePushesBlocked),
		DeletionsBlocked:    rule(ruleDeletionsBlocked),
		LinearHistory:       rule(ruleLinearHistory),
	}
	pct := func(count *int) *int { return percentOf(count, len(protections)) }
	return BranchProtectionRules{
		PullRequestRequired: pct(counts.PullRequestRequired),
		ApprovingReviews:    pct(counts.ApprovingReviews),
		DismissStaleReviews: pct(counts.DismissStaleReviews),
		CodeOwnerReviews:    pct(counts.CodeOwnerReviews),
		StatusChecks:        pct(counts.StatusChecks),
		SignedCommits:       pct(counts.SignedCommits),
		AdminEnforcement:    pct(counts.AdminEnforcement),
		ForcePushesBlocked:  pct(counts.ForcePushesBlocked),
		DeletionsBlocked:    pct(counts.DeletionsBlocked),
		LinearHistory:       pct(counts.LinearHistory),
		RepositoryCounts:    counts,
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
	if m.analysisHidden > 0 {
		out.addPermissionError(fmt.Sprintf(
			"security_and_analysis: GitHub withheld secret scanning, push protection, and Dependabot settings on %d/%d repos, because it returns them only with admin rights (administration:read), so those metrics are null",
			m.analysisHidden, m.totalRepos,
		))
	}
	if m.securitySettingsFailed > 0 {
		out.warnings = append(out.warnings, fmt.Sprintf(
			"security settings: reading repository settings failed on %d/%d repos, so security feature metrics that depend on them are null",
			m.securitySettingsFailed, m.totalRepos,
		))
	}
	if m.codeScanningFailed > 0 {
		out.warnings = append(out.warnings, fmt.Sprintf(
			"code scanning: reading code scanning status failed on %d/%d repos, so code scanning metrics are null",
			m.codeScanningFailed, m.totalRepos,
		))
	}
	if m.branchRulesDenied > 0 {
		out.addPermissionError(fmt.Sprintf(
			"branch rulesets: got 403 on %d/%d repos when reading default-branch rules (needs metadata:read), so branch protection metrics that depend on rulesets are null",
			m.branchRulesDenied, m.totalRepos,
		))
	}
	if m.branchRulesFailed > 0 {
		out.warnings = append(out.warnings, fmt.Sprintf(
			"branch rulesets: reading default-branch rules failed on %d/%d repos, so branch protection metrics that depend on rulesets are null",
			m.branchRulesFailed, m.totalRepos,
		))
	}
	out.warnings = append(out.warnings, m.rulesetWarnings()...)

	out.permissionErrors = append(out.permissionErrors, m.diag.permissionErrors...)
	out.warnings = append(out.warnings, m.diag.warnings...)

	return out.build()
}

// rulesetWarnings reports rulesets that could not be read, bypass lists GitHub
// withheld, and repository-role bypasses whose role GitHub does not document.
func (m *metricsAggregator) rulesetWarnings() []string {
	var unread, hidden, roleBypass int
	for _, rs := range m.rulesetDetails {
		switch {
		case rs == nil:
			unread++
		case !rs.BypassVisible:
			hidden++
		case rulesetHoldsAdmins(rs) == nil:
			roleBypass++
		}
	}
	total := len(m.rulesetDetails)

	var out []string
	if unread > 0 {
		out = append(out, fmt.Sprintf(
			"branch rulesets: could not read %d of %d rulesets, so their names, enforcement, and bypass lists are not reported",
			unread, total))
	}
	if hidden > 0 {
		out = append(out, fmt.Sprintf(
			"branch rulesets: bypass lists for %d of %d rulesets are not visible to this token, because GitHub returns them only with write access to the ruleset. Bypass and admin enforcement are unknown where those rulesets apply.",
			hidden, total))
	}
	if roleBypass > 0 {
		out = append(out, fmt.Sprintf(
			"branch rulesets: a repository role or an unrecognized actor type may bypass %d of %d rulesets. GitHub does not document which role a role ID refers to, so admin enforcement is unknown where those rulesets apply.",
			roleBypass, total))
	}
	return out
}
