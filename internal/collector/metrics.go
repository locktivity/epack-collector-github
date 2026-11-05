package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// metricsAggregator collects repository metrics during iteration.
type metricsAggregator struct {
	// Scope tracking. reposErr is why the repository list could not be read,
	// which leaves every repository-derived value unknown. archivedRepos
	// counts the archived repositories read, which are out of scope and so in
	// excludedRepos too. repositorySelection is the GitHub App installation's
	// repository selection, "" for a token other than an installation token or
	// when it could not be read; for "selected", only the repositories in the
	// selection are counted at all.
	totalRepos          int
	excludedRepos       int
	archivedRepos       int
	reposErr            error
	repositorySelection string

	// repos holds the included repositories and their REST security settings,
	// captured for the audit/internal surface pass.
	repos repoCache

	// The ruleset details read once per ruleset ID (nil for a ruleset that
	// could not be read).
	rulesetDetails map[int64]*github.Ruleset

	// Why each repo's default-branch rules or each ruleset could not be read.
	branchRulesErrs map[string]error // keyed by "owner/repo"
	rulesetErrs     map[int64]error

	// notes accumulates the surface pass's notes.
	notes runNotes

	// lists holds the lists that more than one artifact is built from.
	lists sharedLists
}

// processRepository processes a single repository and updates metrics.
func (m *metricsAggregator) processRepository(repo github.Repository, includePatterns, excludePatterns []string) {
	if repo.IsArchived {
		m.excludedRepos++
		m.archivedRepos++
		return
	}

	if !ShouldIncludeRepo(repo.Name, includePatterns, excludePatterns) {
		m.excludedRepos++
		return
	}

	m.totalRepos++
	m.repos.add(repo)
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
		RepositoryCounts:    &counts,
	}
}

// runNotes returns the run warnings that no gap covers. None of them needs
// action from the customer. One warning reports rulesets that a repository
// role may bypass. Admin enforcement on those rulesets stays unknown whatever
// the collector is granted. The others are the surface pass's notes. A value
// the run could not read needs no warning, because its gap records the reason
// and what to do.
func (m *metricsAggregator) runNotes() []string {
	roleBypass := 0
	for _, rs := range m.rulesetDetails {
		if rs != nil && rs.BypassVisible && rulesetHoldsAdmins(rs) == nil {
			roleBypass++
		}
	}
	var out []string
	if roleBypass > 0 {
		out = append(out, fmt.Sprintf(
			"branch rulesets: a repository role or an unrecognized actor type may bypass %d of %d rulesets. GitHub does not document which role a role ID refers to, so admin enforcement is unknown where those rulesets apply.",
			roleBypass, len(m.rulesetDetails)))
	}
	return append(out, m.notes.list...)
}
