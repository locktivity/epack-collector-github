package collector

// The blocks in this file are the ones epack v0.10.0 moved out of
// vcs-posture, into access-posture and vuln-scanning. The schema keeps them
// as deprecated, and the collector writes them as v0.3 did, so profiles
// written before v0.10.0 grade the same. A later minor removes them.

// VCSPostureOrgSecurity holds the organization's 2FA requirement, left out
// when the detailed artifact reports it as unknown.
type VCSPostureOrgSecurity struct {
	TwoFactorRequired *bool `json:"two_factor_required,omitempty"`
}

// VCSPostureSecurityFeatures holds the share of repositories with each
// scanner on. Each is left out when the detailed artifact reports it as
// unknown, and over no repositories.
type VCSPostureSecurityFeatures struct {
	VulnAlertsPct     *float64 `json:"vuln_alerts_pct,omitempty"`
	SecretScanningPct *float64 `json:"secret_scanning_pct,omitempty"`
	CodeScanningPct   *float64 `json:"code_scanning_pct,omitempty"`
}

// deprecatedBlocks copies the deprecated blocks from the detailed artifact.
func (o *OrgPosture) deprecatedBlocks() (VCSPostureOrgSecurity, VCSPostureSecurityFeatures) {
	return VCSPostureOrgSecurity{TwoFactorRequired: o.AccessControl.TwoFactorRequired},
		VCSPostureSecurityFeatures{
			VulnAlertsPct:     pctFloat(o.SecurityFeatures.VulnerabilityAlerts),
			SecretScanningPct: pctFloat(o.SecurityFeatures.SecretScanning),
			CodeScanningPct:   pctFloat(o.SecurityFeatures.CodeScanning),
		}
}

// pctFloat carries a whole percentage into the normalized artifact, where a
// percentage over no repositories is left out.
func pctFloat(pct *int) *float64 {
	if pct == nil {
		return nil
	}
	return ptr(float64(*pct))
}
