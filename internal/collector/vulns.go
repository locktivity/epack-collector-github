package collector

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// VulnScanning is the normalized evidencepack/vuln-scanning@v1 artifact for
// the organization, with an entry for Dependabot, code scanning, and secret
// scanning. A value the run could not read is left out with a gap. The
// counts are written from the audit level, and the present flags at every
// level.
type VulnScanning struct {
	SchemaVersion string        `json:"schema_version"`
	CollectedAt   string        `json:"collected_at"`
	Provider      string        `json:"provider"`
	Scanners      []VulnScanner `json:"scanners"`
}

// VulnScanner is one scanner's coverage of the in-scope repositories and
// its open alerts. The coverage values are copies of the detailed artifact's
// security features.
type VulnScanner struct {
	Scanner              string           `json:"scanner"`
	Category             string           `json:"category"`
	Enabled              *bool            `json:"enabled,omitempty"`
	ResourcesPresent     *bool            `json:"resources_present,omitempty"`
	ResourceCount        *int             `json:"resource_count,omitempty"`
	ScannedResourceCount *int             `json:"scanned_resource_count,omitempty"`
	CoveragePct          Reading[float64] `json:"coverage_pct,omitzero"`
	OpenCriticalPresent  *bool            `json:"open_critical_present,omitempty"`
	OpenHighPresent      *bool            `json:"open_high_present,omitempty"`
	OverduePresent       *bool            `json:"overdue_present,omitempty"`
	OpenCriticalCount    *int             `json:"open_critical_count,omitempty"`
	OpenHighCount        *int             `json:"open_high_count,omitempty"`
	OpenMediumCount      *int             `json:"open_medium_count,omitempty"`
	OpenLowCount         *int             `json:"open_low_count,omitempty"`
	OverdueCriticalCount *int             `json:"overdue_critical_count,omitempty"`
	OverdueHighCount     *int             `json:"overdue_high_count,omitempty"`
}

// How long an open finding can stay open before it is overdue, as the
// vuln-scanning schema sets it.
const (
	OverdueCriticalDays = 30
	OverdueHighDays     = 90
)

// scanners are the vuln-scanning artifact's entries, in order. feature is
// the security feature whose coverage the entry copies. alerts is the alert
// type whose open alerts it counts. Secret scanning alerts have no severity,
// so that entry has none.
var scanners = []struct {
	name, category string
	feature        feature
	alerts         string
}{
	{"dependabot", "dependencies", featureVulnerabilityAlerts, "dependabot"},
	{"code_scanning", "code", featureCodeScanning, "code_scanning"},
	{"secret_scanning", "secrets", featureSecretScanning, ""},
}

// scannerPointer is the pointer to a field of the vuln-scanning artifact's
// scanner entry i.
func scannerPointer(i int, field string) string { return rowPointer("/scanners", i, field) }

// errAlertsCut is why a count is left out when a repository's alert list
// reached github.AlertFetchCap, so it may hold more alerts.
var errAlertsCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
	fmt.Errorf("a repository has more open alerts of one type than the %d the collector reads", github.AlertFetchCap))

// errNoCreatedAt is why the overdue values are left out when an alert has
// no creation time to take its age from.
var errNoCreatedAt = componentsdk.CodeError(componentsdk.CodeInvalidResponse,
	errors.New("an open alert has no created_at in RFC 3339 format"))

// toVulnScanning builds the vuln-scanning artifact from the detailed
// artifact's security features and the alerts the run listed.
func (c *Collector) toVulnScanning(posture *OrgPosture, m *metricsAggregator) *VulnScanning {
	w := writer{gaps: c.gaps, path: VulnPath, audit: c.gaps.level.AtLeast(componentsdk.LevelAudit)}
	present := posture.Scope.RepositoriesPresent
	noRepositories := present != nil && !*present
	v := &VulnScanning{
		SchemaVersion: SchemaVersion,
		CollectedAt:   posture.CollectedAt,
		Provider:      "github",
		Scanners:      make([]VulnScanner, 0, len(scanners)),
	}
	for i, s := range scanners {
		e := VulnScanner{
			Scanner:              s.name,
			Category:             s.category,
			Enabled:              w.flag(scannerPointer(i, "enabled"), m.featureOnAnywhere(s.feature)),
			ResourcesPresent:     present,
			ResourceCount:        posture.Scope.IncludedRepositoryCount,
			ScannedResourceCount: posture.SecurityFeatures.repositoryCount(s.feature),
			CoveragePct:          percentage(posture.SecurityFeatures.coverage(s.feature), noRepositories),
		}
		if s.alerts == "" {
			w.gaps.unsupported(VulnPath, "Secret scanning alerts have no severity.", append([]string{
				scannerPointer(i, "open_critical_present"), scannerPointer(i, "open_high_present"), scannerPointer(i, "overdue_present"),
			}, w.auditOnly(
				scannerPointer(i, "open_critical_count"), scannerPointer(i, "open_high_count"),
				scannerPointer(i, "open_medium_count"), scannerPointer(i, "open_low_count"),
				scannerPointer(i, "overdue_critical_count"), scannerPointer(i, "overdue_high_count"),
			)...)...)
		} else {
			t := c.tallyAlerts(m, s.alerts)
			e.OpenCriticalPresent = w.flag(scannerPointer(i, "open_critical_present"), t.critical.any())
			e.OpenHighPresent = w.flag(scannerPointer(i, "open_high_present"), t.high.any())
			e.OverduePresent = w.flag(scannerPointer(i, "overdue_present"), t.overduePresent())
			e.OpenCriticalCount = w.count(scannerPointer(i, "open_critical_count"), t.critical.count())
			e.OpenHighCount = w.count(scannerPointer(i, "open_high_count"), t.high.count())
			e.OpenMediumCount = w.count(scannerPointer(i, "open_medium_count"), t.medium.count())
			e.OpenLowCount = w.count(scannerPointer(i, "open_low_count"), t.low.count())
			e.OverdueCriticalCount = w.count(scannerPointer(i, "overdue_critical_count"), t.overdueCritical.count())
			e.OverdueHighCount = w.count(scannerPointer(i, "overdue_high_count"), t.overdueHigh.count())
		}
		v.Scanners = append(v.Scanners, e)
	}
	return v
}

// featureOnAnywhere reports whether any in-scope repository has feature f
// on. It fails when no repository read has it on and some could not be
// read.
func (m *metricsAggregator) featureOnAnywhere(f feature) measure[bool] {
	if m.reposErr != nil {
		return unknown[bool](m.reposErr, 0)
	}
	failed := perRepoFailures{}
	for _, repo := range m.repos.included {
		v, err := m.featureValue(repo, f)
		switch {
		case v == nil:
			failed.add(err)
		case *v:
			return known(true)
		}
	}
	if failed.count > 0 {
		return unknown[bool](failed.err, failed.count)
	}
	return known(false)
}

// coverage is the detailed percentage of in-scope repositories with
// feature f on.
func (s SecurityFeatures) coverage(f feature) *int {
	switch f {
	case featureVulnerabilityAlerts:
		return s.VulnerabilityAlerts
	case featureCodeScanning:
		return s.CodeScanning
	case featureSecretScanning:
		return s.SecretScanning
	case featureSecretScanningPushProtection:
		return s.SecretScanningPushProtection
	default:
		return s.DependabotSecurityUpdates
	}
}

// repositoryCount is the detailed count of in-scope repositories with
// feature f on, nil below the audit level.
func (s SecurityFeatures) repositoryCount(f feature) *int {
	c := s.RepositoryCounts
	if c == nil {
		return nil
	}
	switch f {
	case featureVulnerabilityAlerts:
		return c.VulnerabilityAlerts
	case featureCodeScanning:
		return c.CodeScanning
	case featureSecretScanning:
		return c.SecretScanning
	case featureSecretScanningPushProtection:
		return c.SecretScanningPushProtection
	default:
		return c.DependabotSecurityUpdates
	}
}

// tallied is the number of open alerts of one kind across the in-scope
// repositories. n counts the alerts read. incomplete counts the
// repositories whose list could not be read or was cut short, and err is
// why.
type tallied struct {
	n          int
	incomplete int
	err        error
}

// count is the tally as a count, which fails when any list was incomplete.
func (t tallied) count() measure[int] {
	if t.incomplete > 0 {
		return unknown[int](t.err, t.incomplete)
	}
	return known(t.n)
}

// any reports whether there is any such alert. It is true when one was
// read, and fails when none was read and a list was incomplete.
func (t tallied) any() measure[bool] {
	if t.n > 0 {
		return known(true)
	}
	return anyAbove(false, t.count())
}

// alertTally is one scanner's open alerts by severity, and the overdue ones.
type alertTally struct {
	critical, high, medium, low  tallied
	overdueCritical, overdueHigh tallied
}

// overduePresent reports whether any open alert is overdue.
func (t alertTally) overduePresent() measure[bool] {
	if t.overdueCritical.n+t.overdueHigh.n > 0 {
		return known(true)
	}
	if m := t.overdueCritical.count(); m.err != nil {
		return unknownAs[bool](m)
	}
	return anyAbove(false, t.overdueHigh.count())
}

// tallyAlerts counts the open alerts of type alerts, such as dependabot,
// across the in-scope repositories. A repository whose alert type is not
// enabled has none.
func (c *Collector) tallyAlerts(m *metricsAggregator, alerts string) alertTally {
	var t alertTally
	all := []*tallied{&t.critical, &t.high, &t.medium, &t.low, &t.overdueCritical, &t.overdueHigh}
	incomplete := func(err error) {
		for _, n := range all {
			n.incomplete++
			if n.err == nil {
				n.err = err
			}
		}
	}
	if m.reposErr != nil {
		incomplete(m.reposErr)
		return t
	}
	now := c.now()
	for _, repo := range m.lists.alerts {
		l, _ := repo.list(alerts)
		switch {
		case l.err != nil && !isFeatureUnavailable(l.err):
			incomplete(l.err)
			continue
		case l.more:
			incomplete(errAlertsCut)
		}
		for _, a := range repo.severities(alerts) {
			var counted, overdue *tallied
			days := 0
			switch strings.ToLower(a.severity) {
			case "critical":
				counted, overdue, days = &t.critical, &t.overdueCritical, OverdueCriticalDays
			case "high":
				counted, overdue, days = &t.high, &t.overdueHigh, OverdueHighDays
			case "medium":
				counted = &t.medium
			case "low":
				counted = &t.low
			default:
				continue
			}
			counted.n++
			if overdue == nil {
				continue
			}
			created, err := time.Parse(time.RFC3339, a.createdAt)
			switch {
			case err != nil:
				overdue.incomplete++
				if overdue.err == nil {
					overdue.err = errNoCreatedAt
				}
			case now.Sub(created) > time.Duration(days)*24*time.Hour:
				overdue.n++
			}
		}
	}
	return t
}

// severity is one open alert's severity and creation time.
type severity struct {
	severity, createdAt string
}

// severities returns the severity of each open alert of type alerts. A
// Dependabot alert takes the severity of its vulnerability, and a code
// scanning alert the security severity of its rule, which is empty for a
// rule that is not a security query.
func (a repoAlerts) severities(alerts string) []severity {
	var out []severity
	switch alerts {
	case "dependabot":
		for _, d := range a.deps {
			out = append(out, severity{d.Severity, d.CreatedAt})
		}
	case "code_scanning":
		for _, cs := range a.code {
			out = append(out, severity{cs.SecuritySeverity, cs.CreatedAt})
		}
	}
	return out
}
