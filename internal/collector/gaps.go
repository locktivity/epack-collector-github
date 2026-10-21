package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// Artifact paths in the pack.
const (
	DetailedPath   = "artifacts/github.json"
	NormalizedPath = "artifacts/github.vcs-posture.json"
	// NormalizedSchema is the normalized artifact's schema.
	NormalizedSchema = "evidencepack/vcs-posture@v1"
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
)

// gapLog records each value the collector leaves out in the run's recorder.
// credential is what the run signed in as, once it has.
type gapLog struct {
	rec        *componentsdk.Recorder
	credential *github.Credential
}

func newGapLog(rec *componentsdk.Recorder) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec}
}

// leaveOut records the detailed artifact's values at pointers as left out
// because of err. A nil err records nothing.
func (l *gapLog) leaveOut(err error, pointers ...string) {
	l.rec.Helper()
	if err == nil {
		return
	}
	opts := permissionOptions(err, l.credential)
	for _, pointer := range pointers {
		l.rec.NotCollected(detailed(pointer), err, opts...)
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
	opts := permissionOptions(err, l.credential)
	for _, pointer := range pointers {
		l.rec.Partial(detailed(pointer), unmeasured, err, opts...)
	}
}

func detailed(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: DetailedPath, Pointer: pointer}
}

// normalizedSources maps each normalized field to the detailed field it
// copies, so a gap on the detailed value carries over.
var normalizedSources = []struct{ normalized, detailed string }{
	{"/org_security/two_factor_required", "/access_control/two_factor_required"},
	{"/repo_coverage_pct", "/scope/repositories_coverage"},
	{"/branch_protection/pr_required_pct", "/branch_protection_rules/pull_request_required"},
	{"/branch_protection/approving_reviews_pct", "/branch_protection_rules/approving_reviews"},
	{"/branch_protection/status_checks_pct", "/branch_protection_rules/status_checks"},
	{"/branch_protection/signed_commits_pct", "/branch_protection_rules/signed_commits"},
	{"/security_features/vuln_alerts_pct", "/security_features/vulnerability_alerts"},
	{"/security_features/secret_scanning_pct", "/security_features/secret_scanning"},
	{"/security_features/code_scanning_pct", "/security_features/code_scanning"},
}

func (l *gapLog) mirrorNormalized() {
	for _, source := range normalizedSources {
		l.rec.Mirror(detailed(source.detailed), componentsdk.Location{Path: NormalizedPath, Pointer: source.normalized})
	}
}

// rowPointer is the pointer to a field of one row of a list.
func rowPointer(list string, index int, field string) string {
	return fmt.Sprintf("%s/%d/%s", list, index, field)
}
