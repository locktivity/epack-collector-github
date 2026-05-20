package collector

import (
	"github.com/locktivity/epack-collector-github/internal/github"
)

// FindingsCap bounds emitted alerts per type per repo (5,000 per type per repo);
// on cap-hit a truncation flag + dropped count are emitted.
const FindingsCap = 5000

// SecurityFindings is the internal-level findings inventory across all repos.
// No secret values, no CVE description text.
type SecurityFindings struct {
	SecretScanning []github.SecretScanningAlert `json:"secret_scanning,omitempty"`
	CodeScanning   []github.CodeScanningAlert   `json:"code_scanning,omitempty"`
	Dependabot     []github.DependabotAlert     `json:"dependabot,omitempty"`

	Truncated        bool `json:"truncated,omitempty"`
	TruncatedDropped int  `json:"truncated_dropped,omitempty"`
}

// Code-scanning and Dependabot use different severity vocabularies, so each has
// its own rank table. Unknown/absent values rank 0. Higher survives truncation.
var (
	codeScanningSeverityRank = map[string]int{
		"error":   2,
		"warning": 1,
		"note":    0,
	}
	dependabotSeverityRank = map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}
)

// Truncation comparators: highest severity survives, ties broken by oldest
// created-at first (so the oldest critical findings stick on cap-hit).

func lessSecretScanningAlert(a, b github.SecretScanningAlert) bool {
	// Secret-scanning alerts carry no severity; order by created-at ascending.
	return a.CreatedAt < b.CreatedAt
}

func lessCodeScanningAlert(a, b github.CodeScanningAlert) bool {
	if codeScanningSeverityRank[a.Severity] != codeScanningSeverityRank[b.Severity] {
		return codeScanningSeverityRank[a.Severity] > codeScanningSeverityRank[b.Severity]
	}
	return a.CreatedAt < b.CreatedAt
}

func lessDependabotAlert(a, b github.DependabotAlert) bool {
	if dependabotSeverityRank[a.Severity] != dependabotSeverityRank[b.Severity] {
		return dependabotSeverityRank[a.Severity] > dependabotSeverityRank[b.Severity]
	}
	return a.CreatedAt < b.CreatedAt
}

// collectFindings fetches open secret-scanning, code-scanning, and Dependabot
// alerts per repo, applying the per-type-per-repo cap and accumulating into a
// single inventory sorted severity-desc then created-at-asc on truncation.
func (c *Collector) collectFindings(p *collectionPass) {
	findings := &SecurityFindings{}
	permissionDenied := false
	featureOff := false

	for _, repo := range p.metrics.repos.included {
		owner := repo.Owner.Login
		name := repo.Name

		secrets, moreS, errS := c.client.ListSecretScanningAlerts(p.ctx, owner, name)
		code, moreC, errC := c.client.ListCodeScanningAlerts(p.ctx, owner, name)
		deps, moreD, errD := c.client.ListDependabotAlerts(p.ctx, owner, name)
		for _, e := range []error{errS, errC, errD} {
			switch {
			case isDenied(e):
				permissionDenied = true
			case isFeatureUnavailable(e):
				featureOff = true
			}
		}

		keptS, dropS, truncS := Truncate(secrets, FindingsCap, lessSecretScanningAlert)
		keptC, dropC, truncC := Truncate(code, FindingsCap, lessCodeScanningAlert)
		keptD, dropD, truncD := Truncate(deps, FindingsCap, lessDependabotAlert)

		findings.SecretScanning = append(findings.SecretScanning, keptS...)
		findings.CodeScanning = append(findings.CodeScanning, keptC...)
		findings.Dependabot = append(findings.Dependabot, keptD...)

		if truncS || truncC || truncD || moreS || moreC || moreD {
			findings.Truncated = true
		}
		findings.TruncatedDropped += dropS + dropC + dropD
	}

	recordAlertDiagnostic(p, "security_features.findings", permissionDenied, featureOff)

	p.posture.SecurityFeatures.Findings = findings
}
