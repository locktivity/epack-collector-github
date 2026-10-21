// Package collector provides GitHub organization posture collection functionality.
package collector

import "github.com/locktivity/epack/componentsdk"

// VCSPosture represents the normalized version control system posture.
// This follows the evidencepack/vcs-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic. A metric the detailed artifact
// reports as unknown is left out, with the same gap, and so is a section
// whose every metric is.
type VCSPosture struct {
	SchemaVersion    string                     `json:"schema_version"`
	CollectedAt      string                     `json:"collected_at"`
	Provider         string                     `json:"provider"`
	Organization     string                     `json:"organization"`
	OrgSecurity      VCSPostureOrgSecurity      `json:"org_security,omitzero"`
	RepoCoveragePct  *float64                   `json:"repo_coverage_pct,omitempty"`
	BranchProtection VCSPostureBranchProtection `json:"branch_protection,omitzero"`
	SecurityFeatures VCSPostureSecurityFeatures `json:"security_features,omitzero"`
}

// VCSPostureOrgSecurity contains org-level security settings.
type VCSPostureOrgSecurity struct {
	TwoFactorRequired *bool `json:"two_factor_required,omitempty"`
}

// VCSPostureBranchProtection contains branch protection coverage metrics. A
// metric is omitted when the detailed artifact reports it as unknown.
type VCSPostureBranchProtection struct {
	PRRequiredPct       *float64 `json:"pr_required_pct,omitempty"`
	ApprovingReviewsPct *float64 `json:"approving_reviews_pct,omitempty"`
	StatusChecksPct     *float64 `json:"status_checks_pct,omitempty"`
	SignedCommitsPct    *float64 `json:"signed_commits_pct,omitempty"`
}

// VCSPostureSecurityFeatures contains security feature adoption metrics.
type VCSPostureSecurityFeatures struct {
	VulnAlertsPct     *float64 `json:"vuln_alerts_pct,omitempty"`
	SecretScanningPct *float64 `json:"secret_scanning_pct,omitempty"`
	CodeScanningPct   *float64 `json:"code_scanning_pct,omitempty"`
}

// ToVCSPosture transforms detailed GitHub output to normalized vcs-posture format.
func (o *OrgPosture) ToVCSPosture() *VCSPosture {
	posture := &VCSPosture{
		SchemaVersion:   "1.0.0",
		CollectedAt:     o.CollectedAt,
		Provider:        "github",
		Organization:    o.Organization,
		RepoCoveragePct: pctFloat(o.Scope.RepositoriesCoverage),
		OrgSecurity: VCSPostureOrgSecurity{
			TwoFactorRequired: o.AccessControl.TwoFactorRequired,
		},
		BranchProtection: VCSPostureBranchProtection{
			PRRequiredPct:       pctFloat(o.BranchProtectionRules.PullRequestRequired),
			ApprovingReviewsPct: pctFloat(o.BranchProtectionRules.ApprovingReviews),
			StatusChecksPct:     pctFloat(o.BranchProtectionRules.StatusChecks),
			SignedCommitsPct:    pctFloat(o.BranchProtectionRules.SignedCommits),
		},
		SecurityFeatures: VCSPostureSecurityFeatures{
			VulnAlertsPct:     pctFloat(o.SecurityFeatures.VulnerabilityAlerts),
			SecretScanningPct: pctFloat(o.SecurityFeatures.SecretScanning),
			CodeScanningPct:   pctFloat(o.SecurityFeatures.CodeScanning),
		},
	}

	return posture
}

func pctFloat(pct *int) *float64 {
	if pct == nil {
		return nil
	}
	return ptr(float64(*pct))
}

// Artifacts returns the detailed artifact and the normalized vcs-posture
// artifact derived from it.
func (o *OrgPosture) Artifacts() []componentsdk.CollectedArtifact {
	return []componentsdk.CollectedArtifact{
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
}
