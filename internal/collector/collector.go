package collector

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// Collector collects GitHub organization security posture.
type Collector struct {
	client github.GitHubClient
	config Config
	gaps   *gapLog
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

func (c *Collector) now() time.Time {
	if c.config.Now != nil {
		return c.config.Now()
	}
	return time.Now()
}

// stepper runs the parts of a collection one after another as the run's
// steps, each ending when the next one starts.
type stepper struct {
	ctx     context.Context
	current *componentsdk.Step
}

// next ends the current step and starts the one named name, returning the
// context the step's calls are made with.
func (s *stepper) next(name, title string) context.Context {
	s.end()
	ctx, step := componentsdk.StartStep(s.ctx, name, title)
	s.current = step
	return ctx
}

// end ends the current step, if there is one.
func (s *stepper) end() {
	s.current.End()
	s.current = nil
}

// New creates a new Collector with the given configuration.
// It supports two authentication methods:
//   - GitHub App (recommended): Set AppID, InstallationID, and PrivateKey
//   - Token: Set GitHubToken to an installation token or a classic PAT (legacy)
func New(config Config) (*Collector, error) {
	base := config.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	var client github.GitHubClient
	switch {
	case config.AppID != 0 && config.PrivateKey != "":
		// GitHub App auth (recommended)
		if config.InstallationID == 0 {
			return nil, fmt.Errorf("installation_id is required when using GitHub App authentication")
		}
		appClient, err := github.NewClientFromApp(base, config.AppID, config.InstallationID, []byte(config.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub App client: %w", err)
		}
		client = appClient
	case config.GitHubToken != "":
		// An installation token, or a classic PAT (legacy)
		client = github.NewClient(base, config.GitHubToken)
	default:
		return nil, fmt.Errorf("authentication required: provide app_id + private_key (recommended) or github_token")
	}

	return NewWithClient(config, client), nil
}

// NewWithClient creates a Collector with a custom client (for testing).
func NewWithClient(config Config, client github.GitHubClient) *Collector {
	return &Collector{
		client: client,
		config: config,
		gaps:   newGapLog(config.Recorder),
	}
}

// Collect fetches and aggregates security posture metrics for the organization.
//
// level controls collection depth: trust emits org-level aggregates only;
// audit adds per-repo configs and member/repo inventories; internal adds
// per-user activity, findings inventories, and the audit-log slice. Levels are
// cumulative.
//
// It returns an error only when the sign-in fails. Any value it cannot read
// after that is left out of the artifact and recorded with the reason.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	if c.config.Organization == "" {
		return nil, fmt.Errorf("organization is required")
	}

	includePatterns := c.config.IncludePatterns
	if len(includePatterns) == 0 {
		includePatterns = []string{DefaultIncludePattern}
	}

	posture := NewOrgPosture(c.config.Organization)
	posture.CollectedAt = c.now().UTC().Format(time.RFC3339)
	posture.CollectedAtLevel = string(level)
	c.gaps.level = level

	metrics := &metricsAggregator{}
	steps := &stepper{ctx: ctx}
	defer steps.end()

	orgSecurity, err := c.client.FetchOrgSecurity(steps.next("sign_in", "Sign in"), c.config.Organization)
	if err != nil {
		return nil, fmt.Errorf("signing in to GitHub organization %s: %w", c.config.Organization, err)
	}
	c.recordSignIn(orgSecurity)
	// The organization's name is matched in any case, so the configured name
	// can differ from its login.
	posture.Organization = cmp.Or(orgSecurity.Login, c.config.Organization)

	// A repository list that fails on any page is discarded, because a partial
	// list would skew every repository-derived value.
	reposCtx := steps.next("repositories", "Repositories")
	var listed []github.Repository
	err = c.client.FetchRepositories(reposCtx, c.config.Organization, func(repos []github.Repository) error {
		listed = append(listed, repos...)
		c.status(fmt.Sprintf("Found %d repositories...", len(listed)))
		return nil
	})
	metrics.repositorySelection = orgSecurity.Credential.RepositorySelection
	if err == nil {
		metrics.repositorySelection, listed, err = c.installedOn(reposCtx, orgSecurity.Credential, listed)
	}
	if err != nil {
		// Each value derived from the list is left out with err as its reason.
		metrics.reposErr = err
	} else {
		for _, repo := range listed {
			metrics.processRepository(repo, includePatterns, c.config.ExcludePatterns)
		}
	}

	c.fetchBranchRules(steps.next("branch_rules", "Branch protection and rulesets"), metrics)
	c.fetchSecuritySettings(steps.next("security_settings", "Security settings"), metrics)
	metrics.markHiddenClassic()

	c.populatePosture(posture, orgSecurity, metrics, includePatterns, level)

	if !level.AtLeast(componentsdk.LevelAudit) {
		c.readTrustLists(steps, metrics)
	}
	c.collectSurfaces(steps, posture, metrics, level)
	steps.end()

	if c.config.CollectAccess {
		posture.access = c.toAccessPosture(posture, orgSecurity, metrics)
	}
	if c.config.CollectVulns {
		posture.vulns = c.toVulnScanning(posture, metrics)
	}

	// Notes are recorded last, so the surface collectors' notes come after the
	// core notes.
	for _, n := range metrics.runNotes() {
		c.gaps.note(n)
	}
	c.gaps.mirrorNormalized(c.config.CollectAccess, c.config.CollectVulns)
	c.gaps.movedDeprecated()

	c.status("Collection complete")

	return posture, nil
}

// recordSignIn records the identity the collector signed in as.
func (c *Collector) recordSignIn(sec *github.OrgSecurity) {
	if sec.Credential.Kind == "" {
		return
	}
	if c.config.Grants != nil {
		c.config.Grants.SignedIn(sec.Credential)
	}
	c.gaps.credential = &sec.Credential
	principal := componentsdk.Principal{
		Provider:   "github",
		Kind:       sec.Credential.Kind,
		TenantID:   c.config.Organization,
		AuthMethod: componentsdk.AuthAPIToken,
		Scopes:     sec.Credential.Scopes,
		ID:         sec.Credential.ID,
	}
	if sec.Credential.Kind == github.CredentialAppInstallation {
		principal.AuthMethod = componentsdk.AuthPrivateKeyJWT
		principal.ReadOnly = readOnly(sec.Credential.Scopes)
	}
	c.gaps.rec.SignedInAs(principal)
}

// readOnly reports whether an installation token's permissions all stop at
// read access. A token passed in cannot show that: a classic token's scopes,
// such as repo, grant writes, and other tokens list none.
func readOnly(scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}
	for _, s := range scopes {
		if _, level, _ := strings.Cut(s, ":"); level != "read" {
			return false
		}
	}
	return true
}

// readTrustLists reads the lists that the access-posture and vuln-scanning
// artifacts need below the audit level, where the detailed artifact is not
// written. Each list is read only for an artifact the run writes, as a step
// of its own.
func (c *Collector) readTrustLists(steps *stepper, metrics *metricsAggregator) {
	reposRead := metrics.reposErr == nil
	if c.config.CollectVulns && reposRead {
		c.readAlerts(steps.next("security_alerts", "Security alerts"), metrics, false)
	}
	if !c.config.CollectAccess {
		return
	}
	if reposRead {
		c.readDeployKeys(steps.next("deploy_keys", "Deploy keys"), metrics)
	}
	_, _, _ = c.readInstallations(steps.next("apps", "Installed Apps"), metrics)
	_, _, _ = c.readGrants(steps.next("tokens", "Fine-grained personal access tokens"), metrics)
	_, _ = c.readMembership(steps.next("members", "Members and outside collaborators"), metrics, false)
	_, _ = c.readSSO(steps.next("sso", "SAML single sign-on"), metrics)
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

// collectSurfaces runs the audit- and internal-gated surface collectors, each
// as a step of the run. At trust it is a no-op, so trust output is unchanged.
// augment* methods extend structs that already exist at trust (access
// control, security features); collect* methods populate the
// audit/internal-only surfaces.
func (c *Collector) collectSurfaces(steps *stepper, posture *OrgPosture, metrics *metricsAggregator, level componentsdk.Level) {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return
	}

	p := &collectionPass{
		posture: posture,
		metrics: metrics,
		level:   level,
		org:     c.config.Organization,
	}
	step := func(name, title string) { p.ctx = steps.next(name, title) }

	step("org_settings", "Organization settings")
	c.augmentAccessControl(p)
	step("security_alerts", "Security alerts")
	c.augmentSecurityFeatures(p)
	c.collectRepositories(p)
	step("codeowners", "CODEOWNERS files")
	c.collectCodeowners(p)
	step("webhooks", "Webhooks")
	c.collectWebhooks(p)
	step("deploy_keys", "Deploy keys")
	c.collectDeployKeys(p)
	step("actions", "Actions runners and secrets")
	c.collectActions(p)
	step("environments", "Deployment environments")
	c.collectEnvironments(p)
	// Per-member last-activity comes from the audit log, so it runs before the
	// member inventory and feeds it the actor→last-activity map.
	step("audit_log", "Audit log")
	activity, activityErr := c.collectAuditLog(p)
	step("apps", "Installed Apps")
	c.collectApps(p)
	step("tokens", "Fine-grained personal access tokens")
	c.collectTokens(p)
	step("members", "Members and outside collaborators")
	c.collectMembers(p, activity, activityErr)
	// The SAML identities feed the detailed member rows and the access file,
	// so they are read when the run writes either.
	if c.config.CollectDetails || c.config.CollectAccess {
		step("sso", "SAML single sign-on")
		c.collectSAMLIdentities(p)
	}
}

// augmentAccessControl adds audit-level org access-control fields (default repo
// permission, members-can-create-repositories) from GET /orgs/{org}. On a
// permission denial the fields stay unset and a diagnostic is recorded.
func (c *Collector) augmentAccessControl(p *collectionPass) {
	const permission, canCreate = "/access_control/default_repository_permission", "/access_control/members_can_create_repositories"
	settings, err := c.client.GetOrgSettings(p.ctx, p.org)
	if err != nil {
		c.gaps.leaveOut(err, permission, canCreate)
		return
	}
	p.posture.AccessControl.DefaultRepositoryPermission = settings.DefaultRepositoryPermission
	p.posture.AccessControl.MembersCanCreateRepositories = settings.MembersCanCreateRepositories
	if settings.DefaultRepositoryPermission == "" {
		c.gaps.leaveOut(errOrgSettingsHidden, permission)
	}
	if settings.MembersCanCreateRepositories == nil {
		c.gaps.leaveOut(errOrgSettingsHidden, canCreate)
	}
}

// fetchBranchRules reads the ruleset rules on each included repo's default
// branch, reads each ruleset's details once, and records the repo's effective
// protection. A failed rules read leaves that repo's ruleset rules unknown.
func (c *Collector) fetchBranchRules(ctx context.Context, metrics *metricsAggregator) {
	metrics.rulesetDetails = map[int64]*github.Ruleset{}
	metrics.branchRulesErrs = map[string]error{}
	metrics.rulesetErrs = map[int64]error{}
	total := int64(len(metrics.repos.included))
	for i, repo := range metrics.repos.included {
		owner, name := repo.Owner.Login, repo.Name
		classic := repo.DefaultBranchRef.BranchProtectionRule
		c.progress(int64(i+1), total, fmt.Sprintf("Reading branch rules for %s", name))

		var rules []github.BranchRule
		if branch := repo.DefaultBranchRef.Name; branch != "" {
			var err error
			rules, err = c.client.GetBranchRules(ctx, owner, name, branch)
			if err != nil {
				metrics.branchRulesErrs[owner+"/"+name] = err
				metrics.repos.recordProtection(owner, name, evaluateProtection(classic, nil, false, nil))
				continue
			}
		}
		for _, rule := range rules {
			if _, seen := metrics.rulesetDetails[rule.RulesetID]; !seen {
				rs, err := c.client.GetRepoRuleset(ctx, owner, name, rule.RulesetID)
				if err != nil {
					metrics.rulesetErrs[rule.RulesetID] = err
				}
				metrics.rulesetDetails[rule.RulesetID] = rs
			}
		}
		metrics.repos.recordProtection(owner, name, evaluateProtection(classic, rules, true, metrics.rulesetDetails))
	}
}

// fetchSecuritySettings fetches REST API security settings for all repositories.
func (c *Collector) fetchSecuritySettings(ctx context.Context, metrics *metricsAggregator) {
	total := int64(len(metrics.repos.included))
	for i, repo := range metrics.repos.included {
		owner, name := repo.Owner.Login, repo.Name
		c.progress(int64(i+1), total, fmt.Sprintf("Checking security settings for %s", name))
		settings, err := c.client.FetchSecuritySettings(ctx, owner, name)
		if err != nil {
			metrics.repos.recordSettingsErr(owner, name, err)
			continue
		}
		metrics.repos.recordSettings(owner, name, settings)
	}
}

// markHiddenClassic marks each included repository whose classic branch
// protection GitHub may have hidden. GitHub hides both security_and_analysis
// and the classic protection from a caller without admin rights on the
// repository, so one whose block came back hidden, with no classic rule,
// may still have one.
func (m *metricsAggregator) markHiddenClassic() {
	for _, repo := range m.repos.included {
		owner, name := repo.Owner.Login, repo.Name
		s := m.repos.settingsFor(owner, name)
		if s == nil || !errors.Is(s.AnalysisErr, github.ErrAnalysisHidden) || repo.DefaultBranchRef.BranchProtectionRule != nil {
			continue
		}
		prot := m.repos.protectionFor(repo)
		prot.hideClassic()
		m.repos.recordProtection(owner, name, prot)
	}
}

// installedOn returns the GitHub App installation's repository selection and
// the listed repositories it is installed on. GitHub lists every public
// repository to any caller, so an App installed on selected repositories also
// sees public ones it cannot read the settings of. An installation token
// passed in has no token exchange to report its selection, so the collector
// always calls the list. Any other token's selection is "", since GitHub has
// no call that lists the repositories such a token can read.
func (c *Collector) installedOn(ctx context.Context, cred github.Credential, listed []github.Repository) (string, []github.Repository, error) {
	if !cred.Installation() || cred.RepositorySelection == github.RepositorySelectionAll {
		return cred.RepositorySelection, listed, nil
	}
	installed, err := c.client.FetchInstallationRepositories(ctx)
	if err != nil {
		return cred.RepositorySelection, nil, err
	}
	if installed.Selection == github.RepositorySelectionAll {
		return installed.Selection, listed, nil
	}
	var kept []github.Repository
	for _, repo := range listed {
		if installed.Names[strings.ToLower(repo.Name)] {
			kept = append(kept, repo)
		}
	}
	return installed.Selection, kept, nil
}

// errRepositoryCountShort leaves out a count of the organization's
// repositories that is below the repositories the GitHub App lists, which
// would put the coverage over 100.
var errRepositoryCountShort = componentsdk.CodeError(componentsdk.CodeInvalidResponse,
	errors.New("GitHub counts fewer repositories in the organization than the GitHub App lists"))

// organizationRepositoryCount is the number of repositories the coverage is
// taken over. A GitHub App installed on selected repositories cannot list the
// private ones outside its selection, so the count is GitHub's own.
func organizationRepositoryCount(sec *github.OrgSecurity, metrics *metricsAggregator) (int, error) {
	listed := metrics.totalRepos + metrics.excludedRepos
	switch {
	case metrics.repositorySelection != github.RepositorySelectionSelected:
		return listed, nil
	case sec.RepositoryCount == nil:
		return 0, errRepositoryCountHidden
	case *sec.RepositoryCount < listed:
		return 0, errRepositoryCountShort
	}
	return *sec.RepositoryCount, nil
}

// repoDerivedPointers are the trust-level values computed from the repository
// list, all left out when the list cannot be read.
var repoDerivedPointers = []string{
	"/scope/repositories_present",
	"/scope/repositories_coverage",
	"/scope/repository_count",
	"/scope/included_repository_count",
	"/posture/branch_protection_coverage",
	"/posture/protected_repository_count",
	"/posture/security_features_coverage",
}

// populatePosture fills in the posture struct from collected metrics. The
// repository counts behind the percentages are written from the audit level.
func (c *Collector) populatePosture(posture *OrgPosture, orgSecurity *github.OrgSecurity, metrics *metricsAggregator, includePatterns []string, level componentsdk.Level) {
	audit := level.AtLeast(componentsdk.LevelAudit)
	count := func(n *int) *int {
		if !audit {
			return nil
		}
		return n
	}
	excludePatterns := c.config.ExcludePatterns
	if excludePatterns == nil {
		excludePatterns = []string{}
	}

	posture.Scope = Scope{
		IncludePatterns: includePatterns,
		ExcludePatterns: excludePatterns,
	}
	if metrics.repositorySelection != "" {
		posture.Scope.RepositorySelection = ptr(metrics.repositorySelection)
	} else if orgSecurity.Credential.Installation() {
		c.gaps.leaveOut(metrics.reposErr, "/scope/repository_selection")
	}
	posture.AccessControl = AccessControl{
		TwoFactorRequired: orgSecurity.TwoFactorRequired,
	}
	if orgSecurity.TwoFactorRequired == nil {
		c.gaps.leaveOut(errTwoFactorHidden, "/access_control/two_factor_required")
	}

	if metrics.reposErr != nil {
		c.gaps.leaveOut(metrics.reposErr, repoDerivedPointers...)
		for _, r := range branchProtectionRollups(posture) {
			c.gaps.leaveOut(metrics.reposErr, r.pointer, r.countPointer)
		}
		for _, f := range features {
			c.gaps.leaveOut(metrics.reposErr, f.pointer(), f.countPointer())
		}
		return
	}
	posture.BranchProtectionRules = metrics.toBranchProtectionRules()
	if !audit {
		posture.BranchProtectionRules.RepositoryCounts = nil
	}

	posture.Scope.RepositoriesPresent = ptr(metrics.totalRepos > 0)
	posture.Scope.IncludedRepositoryCount = count(ptr(metrics.totalRepos))
	if orgRepos, err := organizationRepositoryCount(orgSecurity, metrics); err != nil {
		c.gaps.leaveOut(err, "/scope/repository_count", "/scope/repositories_coverage")
	} else {
		posture.Scope.RepositoryCount = count(ptr(orgRepos))
		if orgRepos > 0 {
			posture.Scope.RepositoriesCoverage = ptr(percent(metrics.totalRepos, orgRepos))
		}
	}

	coverage := metrics.securityFeaturesCoverage()
	c.gaps.partial(coverage.unknown, coverage.err, "/posture/security_features_coverage")
	protected := metrics.protectedRepositoryCount()
	posture.Posture = Posture{
		BranchProtectionCoverage: percentOf(protected, len(metrics.repos.included)),
		ProtectedRepositoryCount: count(protected),
		SecurityFeaturesCoverage: coverage.pct,
	}
	c.recordBranchProtectionGaps(posture, metrics)

	byFeature := map[feature]rollup{}
	for _, f := range features {
		r := metrics.featureRollup(f)
		byFeature[f] = r
		c.gaps.partial(r.unknown, r.err, f.pointer(), f.countPointer())
	}
	posture.SecurityFeatures = SecurityFeatures{
		VulnerabilityAlerts:          byFeature[featureVulnerabilityAlerts].pct,
		CodeScanning:                 byFeature[featureCodeScanning].pct,
		SecretScanning:               byFeature[featureSecretScanning].pct,
		SecretScanningPushProtection: byFeature[featureSecretScanningPushProtection].pct,
		DependabotSecurityUpdates:    byFeature[featureDependabotSecurityUpdates].pct,
	}
	if audit {
		posture.SecurityFeatures.RepositoryCounts = &SecurityFeatureCounts{
			VulnerabilityAlerts:          byFeature[featureVulnerabilityAlerts].count,
			CodeScanning:                 byFeature[featureCodeScanning].count,
			SecretScanning:               byFeature[featureSecretScanning].count,
			SecretScanningPushProtection: byFeature[featureSecretScanningPushProtection].count,
			DependabotSecurityUpdates:    byFeature[featureDependabotSecurityUpdates].count,
		}
	}
}

// percent calculates the percentage of count over total, returning 0 if total is 0.
func percent(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count * MaxPercentage) / total
}
