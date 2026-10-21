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

// collectFindings builds the findings inventory from the alerts listed for
// the per-repo counts, applying the per-type-per-repo cap and sorting
// severity-desc then created-at-asc on truncation. An inventory that could
// not be read for every repo is left out, since a list missing some repos'
// alerts would read as complete.
func (c *Collector) collectFindings(p *collectionPass, listings []repoAlerts) {
	findings := &SecurityFindings{}
	unread := map[string]int{}
	reasons := map[string]error{}

	for _, a := range listings {
		for _, l := range a.lists {
			if l.err == nil || isFeatureUnavailable(l.err) {
				if l.more {
					findings.Truncated = true
				}
				continue
			}
			unread[l.findings]++
			if reasons[l.findings] == nil {
				reasons[l.findings] = l.err
			}
		}

		keptS, dropS, truncS := Truncate(a.secrets, FindingsCap, lessSecretScanningAlert)
		keptC, dropC, truncC := Truncate(a.code, FindingsCap, lessCodeScanningAlert)
		keptD, dropD, truncD := Truncate(a.deps, FindingsCap, lessDependabotAlert)

		findings.SecretScanning = append(findings.SecretScanning, keptS...)
		findings.CodeScanning = append(findings.CodeScanning, keptC...)
		findings.Dependabot = append(findings.Dependabot, keptD...)

		if truncS || truncC || truncD {
			findings.Truncated = true
		}
		findings.TruncatedDropped += dropS + dropC + dropD
	}

	if unread["secret_scanning"] > 0 {
		findings.SecretScanning = nil
	}
	if unread["code_scanning"] > 0 {
		findings.CodeScanning = nil
	}
	if unread["dependabot"] > 0 {
		findings.Dependabot = nil
	}
	for _, list := range []string{"secret_scanning", "code_scanning", "dependabot"} {
		c.gaps.partial(unread[list], reasons[list], "/security_features/findings/"+list)
	}

	permissionDenied, featureOff := alertListProblems(listings)
	recordAlertDiagnostic(p, "security_features.findings", permissionDenied, featureOff)

	p.posture.SecurityFeatures.Findings = findings
}
