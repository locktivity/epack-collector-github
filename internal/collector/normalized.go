// Package collector provides GitHub organization posture collection functionality.
package collector

import (
	"encoding/json"

	"github.com/locktivity/epack/componentsdk"
)

// VCSPosture represents the normalized version control system posture.
// This follows the evidencepack/vcs-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic. A metric the detailed artifact
// reports as unknown is left out, with the same gap, and so is a section
// whose every metric is. A percentage over no repositories is null.
// RepositoriesPresent is written at every level and is false when no
// repository is in scope. The repository counts are written from the audit
// level, as the schema specifies.
type VCSPosture struct {
	SchemaVersion          string                     `json:"schema_version"`
	CollectedAt            string                     `json:"collected_at"`
	Provider               string                     `json:"provider"`
	Organization           string                     `json:"organization"`
	RepositoriesPresent    *bool                      `json:"repositories_present,omitempty"`
	RepositoryCount        *int                       `json:"repository_count,omitempty"`
	ScannedRepositoryCount *int                       `json:"scanned_repository_count,omitempty"`
	RepoCoveragePct        Reading[float64]           `json:"repo_coverage_pct,omitzero"`
	BranchProtection       VCSPostureBranchProtection `json:"branch_protection,omitzero"`
}

// Reading is a normalized value that may have no reading in the detailed
// artifact. It is left out when Read is false. Otherwise it is written as
// Value, which is nil for a percentage over no repositories.
type Reading[T any] struct {
	Value *T
	Read  bool
}

// IsZero reports whether the value has no reading, for omitzero.
func (r Reading[T]) IsZero() bool { return !r.Read }

// MarshalJSON writes the value, or null.
func (r Reading[T]) MarshalJSON() ([]byte, error) { return json.Marshal(r.Value) }

// VCSPostureBranchProtection contains branch protection coverage metrics.
// From the audit level it also holds how many repositories meet each one.
type VCSPostureBranchProtection struct {
	PRRequiredRepositoryCount       *int             `json:"pr_required_repository_count,omitempty"`
	ApprovingReviewsRepositoryCount *int             `json:"approving_reviews_repository_count,omitempty"`
	StatusChecksRepositoryCount     *int             `json:"status_checks_repository_count,omitempty"`
	SignedCommitsRepositoryCount    *int             `json:"signed_commits_repository_count,omitempty"`
	PRRequiredPct                   Reading[float64] `json:"pr_required_pct,omitzero"`
	ApprovingReviewsPct             Reading[float64] `json:"approving_reviews_pct,omitzero"`
	StatusChecksPct                 Reading[float64] `json:"status_checks_pct,omitzero"`
	SignedCommitsPct                Reading[float64] `json:"signed_commits_pct,omitzero"`
}

// ToVCSPosture transforms detailed GitHub output to normalized vcs-posture format.
// It copies the repository counts as they are in the detailed artifact. They
// are present from the audit level.
func (o *OrgPosture) ToVCSPosture() *VCSPosture {
	present := o.Scope.RepositoriesPresent
	noRepositories := present != nil && !*present
	pct := func(p *int) Reading[float64] { return percentage(p, noRepositories) }
	bp := o.BranchProtectionRules
	bpCounts := BranchProtectionRuleCounts{}
	if bp.RepositoryCounts != nil {
		bpCounts = *bp.RepositoryCounts
	}
	posture := &VCSPosture{
		SchemaVersion:          "1.0.0",
		CollectedAt:            o.CollectedAt,
		Provider:               "github",
		Organization:           o.Organization,
		RepositoriesPresent:    present,
		RepositoryCount:        o.Scope.RepositoryCount,
		ScannedRepositoryCount: o.Scope.IncludedRepositoryCount,
		// An organization with no repositories has none in scope, so its
		// coverage is null, like the other percentages.
		RepoCoveragePct: percentage(o.Scope.RepositoriesCoverage, noRepositories),
		BranchProtection: VCSPostureBranchProtection{
			PRRequiredRepositoryCount:       bpCounts.PullRequestRequired,
			ApprovingReviewsRepositoryCount: bpCounts.ApprovingReviews,
			StatusChecksRepositoryCount:     bpCounts.StatusChecks,
			SignedCommitsRepositoryCount:    bpCounts.SignedCommits,
			PRRequiredPct:                   pct(bp.PullRequestRequired),
			ApprovingReviewsPct:             pct(bp.ApprovingReviews),
			StatusChecksPct:                 pct(bp.StatusChecks),
			SignedCommitsPct:                pct(bp.SignedCommits),
		},
	}
	return posture
}

// percentage returns the normalized reading of a detailed percentage. It
// returns pct's value when pct is set. When pct is nil, it returns null if
// none is true, meaning no repository is in scope. Otherwise it returns no
// reading, because the detailed artifact left the value out with a gap.
func percentage(pct *int, none bool) Reading[float64] {
	switch {
	case pct != nil:
		return Reading[float64]{Value: ptr(float64(*pct)), Read: true}
	case none:
		return Reading[float64]{Read: true}
	default:
		return Reading[float64]{}
	}
}

// Artifacts returns the detailed artifact, the normalized vcs-posture
// artifact derived from it, and the access-posture and vuln-scanning
// artifacts when the run built them.
func (o *OrgPosture) Artifacts() []componentsdk.CollectedArtifact {
	artifacts := []componentsdk.CollectedArtifact{
		{
			Data: o,
			Path: DetailedPath,
		},
		{
			Data:   o.ToVCSPosture(),
			Schema: NormalizedSchema,
			Path:   NormalizedPath,
		},
	}
	if o.access != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: o.access, Schema: AccessSchema, Path: AccessPath})
	}
	if o.vulns != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: o.vulns, Schema: VulnSchema, Path: VulnPath})
	}
	return artifacts
}
