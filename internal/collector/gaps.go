package collector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// Artifact paths in the pack.
const (
	DetailedPath   = "artifacts/github.details.json"
	NormalizedPath = "artifacts/github.vcs-posture.json"
	// NormalizedSchema is the normalized artifact's schema.
	NormalizedSchema = "evidencepack/vcs-posture@v1"
	// AccessSchema is the schema of the normalized artifact on who can get
	// into the organization.
	AccessSchema = "evidencepack/access-posture@v1"
	// VulnSchema is the schema of the normalized artifact on vulnerability
	// scanners.
	VulnSchema = "evidencepack/vuln-scanning@v1"
)

// The paths of the access-posture and vuln-scanning artifacts.
var (
	AccessPath = componentsdk.ArtifactPath("github", AccessSchema)
	VulnPath   = componentsdk.ArtifactPath("github", VulnSchema)
)

// Values GitHub withholds from callers without enough access. Each is left
// out with one of these as its reason.
var (
	errTwoFactorHidden = componentsdk.CodeError(componentsdk.CodePermissionDenied,
		errors.New("GitHub returns two_factor_requirement_enabled only to organization owners"))
	errOrgSettingsHidden = componentsdk.CodeError(componentsdk.CodePermissionDenied,
		errors.New("GitHub returns organization settings only to organization owners"))
	errBypassHidden = componentsdk.CodeError(componentsdk.CodePermissionDenied,
		errors.New("GitHub returns a ruleset's bypass list only to callers with write access to the ruleset"))
	errRepositoryCountHidden = componentsdk.CodeError(componentsdk.CodePermissionDenied,
		errors.New("GitHub returns owned_private_repos only to organization owners"))
	errClassicHidden = componentsdk.CodeError(componentsdk.CodePermissionDenied,
		errors.New("GitHub returns a repository's classic branch protection only to callers with admin rights on it, and returns none, with no error, to others"))
)

// gapLog records each value the collector leaves out in the run's recorder.
// credential is the identity the run signed in as, and is nil before sign-in.
// level is the level the run collects at.
type gapLog struct {
	rec        *componentsdk.Recorder
	credential *github.Credential
	level      componentsdk.Level
}

// auditCounts lists the detailed artifact's repository counts, each as a
// pointer or a pointer prefix ending in /. The run writes them from the audit
// level.
var auditCounts = []string{
	"/scope/repository_count",
	"/scope/included_repository_count",
	"/posture/protected_repository_count",
	"/branch_protection_rules/repository_counts/",
	"/security_features/repository_counts/",
}

// writes reports whether the run writes the detailed value at pointer at its
// level. Only a value the run writes gets a gap. Below the audit level it
// writes no count.
func (l *gapLog) writes(pointer string) bool {
	if l.level.AtLeast(componentsdk.LevelAudit) {
		return true
	}
	for _, count := range auditCounts {
		if pointer == count || strings.HasSuffix(count, "/") && strings.HasPrefix(pointer, count) {
			return false
		}
	}
	return true
}

func newGapLog(rec *componentsdk.Recorder) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec}
}

// leaveOut records the detailed artifact's values at pointers as left out
// because of err, with the advice gapAdvice returns for err. It records
// nothing when err is nil.
func (l *gapLog) leaveOut(err error, pointers ...string) {
	l.rec.Helper()
	l.leaveOutAdvised(err, gapAdvice(err, l.credential), pointers...)
}

// leaveOutAdvised is leaveOut with the caller's advice in opts, such as the
// plan a feature requires. It does not call gapAdvice.
func (l *gapLog) leaveOutAdvised(err error, opts []componentsdk.AdviceOption, pointers ...string) {
	l.rec.Helper()
	if err == nil {
		return
	}
	for _, pointer := range pointers {
		if l.writes(pointer) {
			l.rec.NotCollected(detailed(pointer), err, opts...)
		}
	}
}

// partial records the rollups at pointers as left out because unmeasured of
// the repositories they cover could not be read, err being one of the
// failures.
func (l *gapLog) partial(unmeasured int, err error, pointers ...string) {
	l.rec.Helper()
	if err == nil || unmeasured == 0 {
		l.leaveOut(err, pointers...)
		return
	}
	opts := gapAdvice(err, l.credential)
	for _, pointer := range pointers {
		if l.writes(pointer) {
			l.rec.Partial(detailed(pointer), unmeasured, err, opts...)
		}
	}
}

func detailed(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: DetailedPath, Pointer: pointer}
}

// normalizedSources maps each normalized field to the detailed field it
// copies, so a gap on the detailed value carries over. audit is true for the
// repository counts. The run writes them to the normalized artifact from the
// audit level only.
var normalizedSources = []struct {
	normalized, detailed string
	audit                bool
}{
	{"/repositories_present", "/scope/repositories_present", false},
	{"/repository_count", "/scope/repository_count", true},
	{"/scanned_repository_count", "/scope/included_repository_count", true},
	{"/repo_coverage_pct", "/scope/repositories_coverage", false},
	{"/branch_protection/pr_required_pct", "/branch_protection_rules/pull_request_required", false},
	{"/branch_protection/pr_required_repository_count", "/branch_protection_rules/repository_counts/pull_request_required", true},
	{"/branch_protection/approving_reviews_pct", "/branch_protection_rules/approving_reviews", false},
	{"/branch_protection/approving_reviews_repository_count", "/branch_protection_rules/repository_counts/approving_reviews", true},
	{"/branch_protection/status_checks_pct", "/branch_protection_rules/status_checks", false},
	{"/branch_protection/status_checks_repository_count", "/branch_protection_rules/repository_counts/status_checks", true},
	{"/branch_protection/signed_commits_pct", "/branch_protection_rules/signed_commits", false},
	{"/branch_protection/signed_commits_repository_count", "/branch_protection_rules/repository_counts/signed_commits", true},
	// The deprecated blocks in deprecated.go.
	{"/org_security/two_factor_required", "/access_control/two_factor_required", false},
	{"/security_features/vuln_alerts_pct", "/security_features/vulnerability_alerts", false},
	{"/security_features/secret_scanning_pct", "/security_features/secret_scanning", false},
	{"/security_features/code_scanning_pct", "/security_features/code_scanning", false},
}

// mirrorNormalized records each normalized value copied from the detailed
// artifact, so a gap on the detailed value carries over. The access-posture
// and vuln-scanning copies are recorded only when the run writes those
// artifacts.
func (l *gapLog) mirrorNormalized(access, vulns bool) {
	for _, source := range normalizedSources {
		l.mirror(NormalizedPath, source.normalized, source.detailed, source.audit)
	}
	if access {
		l.mirror(AccessPath, "/sign_in/mfa_required", "/access_control/two_factor_required", false)
	}
	if vulns {
		for i, s := range scanners {
			l.mirror(VulnPath, scannerPointer(i, "resources_present"), "/scope/repositories_present", false)
			l.mirror(VulnPath, scannerPointer(i, "resource_count"), "/scope/included_repository_count", true)
			l.mirror(VulnPath, scannerPointer(i, "scanned_resource_count"), s.feature.countPointer(), true)
			l.mirror(VulnPath, scannerPointer(i, "coverage_pct"), s.feature.pointer(), false)
		}
	}
}

// mirror records the value at pointer in the artifact at path as a copy of
// the detailed value at from. audit marks a count, which the run writes from
// the audit level only.
func (l *gapLog) mirror(path, pointer, from string, audit bool) {
	if audit && !l.level.AtLeast(componentsdk.LevelAudit) {
		return
	}
	l.rec.Mirror(detailed(from), componentsdk.Location{Path: path, Pointer: pointer})
}

// leaveOutOf records the values at pointers in the artifact at path as left
// out because of err. unmeasured is the number of items a rollup could not
// read, or 0 for a value left out whole. It records nothing when err is nil.
func (l *gapLog) leaveOutOf(path string, err error, unmeasured int, pointers ...string) {
	l.rec.Helper()
	if err == nil {
		return
	}
	opts := gapAdvice(err, l.credential)
	for _, pointer := range pointers {
		at := componentsdk.Location{Path: path, Pointer: pointer}
		if unmeasured > 0 {
			l.rec.Partial(at, unmeasured, err, opts...)
		} else {
			l.rec.NotCollected(at, err, opts...)
		}
	}
}

// unsupported records the values at pointers in the artifact at path as
// values with no data in GitHub, with detail saying why.
func (l *gapLog) unsupported(path, detail string, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.rec.NotCollectedCode(componentsdk.Location{Path: path, Pointer: pointer}, componentsdk.CodeUnsupported, detail)
	}
}

// notRead records the values at pointers in the artifact at path as values
// GitHub reports that the collector does not read, with detail naming
// where GitHub reports them.
func (l *gapLog) notRead(path, detail string, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.rec.NotCollectedCode(componentsdk.Location{Path: path, Pointer: pointer}, componentsdk.CodeNotRead, detail)
	}
}

// rowPointer is the pointer to a field of one row of a list.
func rowPointer(list string, index int, field string) string {
	return fmt.Sprintf("%s/%d/%s", list, index, field)
}
