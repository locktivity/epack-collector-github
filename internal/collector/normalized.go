// Package collector provides GitHub organization posture collection functionality.
package collector

import "time"

// VCSPosture represents the normalized version control system posture.
// This follows the evidencepack/vcs-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic.
type VCSPosture struct {
	SchemaVersion    string                     `json:"schema_version"`
	CollectedAt      string                     `json:"collected_at"`
	Provider         string                     `json:"provider"`
	Organization     string                     `json:"organization"`
	OrgSecurity      VCSPostureOrgSecurity      `json:"org_security"`
	RepoCoveragePct  float64                    `json:"repo_coverage_pct"`
	BranchProtection VCSPostureBranchProtection `json:"branch_protection"`
	SecurityFeatures VCSPostureSecurityFeatures `json:"security_features"`
}

// VCSPostureOrgSecurity contains org-level security settings.
type VCSPostureOrgSecurity struct {
	TwoFactorRequired bool `json:"two_factor_required"`
}

// VCSPostureBranchProtection contains branch protection coverage metrics.
type VCSPostureBranchProtection struct {
	PRRequiredPct       float64 `json:"pr_required_pct"`
	ApprovingReviewsPct float64 `json:"approving_reviews_pct"`
	StatusChecksPct     float64 `json:"status_checks_pct"`
	SignedCommitsPct    float64 `json:"signed_commits_pct"`
}

// VCSPostureSecurityFeatures contains security feature adoption metrics.
type VCSPostureSecurityFeatures struct {
	VulnAlertsPct     float64 `json:"vuln_alerts_pct"`
	SecretScanningPct float64 `json:"secret_scanning_pct"`
	CodeScanningPct   float64 `json:"code_scanning_pct"`
}

// ToVCSPosture transforms detailed GitHub output to normalized vcs-posture format.
func (o *OrgPosture) ToVCSPosture() *VCSPosture {
	posture := &VCSPosture{
		SchemaVersion:   "1.0.0",
		CollectedAt:     time.Now().UTC().Format(time.RFC3339),
		Provider:        "github",
		Organization:    o.Organization,
		RepoCoveragePct: float64(o.Scope.RepositoriesCoverage),
		OrgSecurity: VCSPostureOrgSecurity{
			TwoFactorRequired: o.AccessControl.TwoFactorRequired != nil && *o.AccessControl.TwoFactorRequired,
		},
		BranchProtection: VCSPostureBranchProtection{
			PRRequiredPct:       float64(o.BranchProtectionRules.PullRequestRequired),
			ApprovingReviewsPct: float64(o.BranchProtectionRules.ApprovingReviews),
			StatusChecksPct:     float64(o.BranchProtectionRules.StatusChecks),
			SignedCommitsPct:    float64(o.BranchProtectionRules.SignedCommits),
		},
		SecurityFeatures: VCSPostureSecurityFeatures{
			VulnAlertsPct:     float64(o.SecurityFeatures.VulnerabilityAlerts),
			SecretScanningPct: float64(o.SecurityFeatures.SecretScanning),
			CodeScanningPct:   float64(o.SecurityFeatures.CodeScanning),
		},
	}

	return posture
}
