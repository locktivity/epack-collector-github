package collector

import (
	"context"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

var vulnClock = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// vulnsAt runs the mock at level with vuln-scanning collected and returns
// the artifact and the gaps.
func vulnsAt(t *testing.T, level componentsdk.Level, mock *mockGitHubClient) (*VulnScanning, []componentsdk.Gap) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{
		Organization: "test-org", IncludePatterns: []string{"*"}, Recorder: rec,
		CollectVulns: true, Now: func() time.Time { return vulnClock },
	}, mock)
	posture, err := c.Collect(t.Context(), level)
	if err != nil {
		t.Fatal(err)
	}
	if posture.vulns == nil || len(posture.vulns.Scanners) != 3 {
		t.Fatalf("vuln-scanning = %+v, want three scanners", posture.vulns)
	}
	return posture.vulns, rec.Gaps()
}

func vulnGap(gaps []componentsdk.Gap, pointer string) *componentsdk.Gap {
	for i, g := range gaps {
		if g.Path == VulnPath && g.Pointer == pointer {
			return &gaps[i]
		}
	}
	return nil
}

// ago is the time days and extra before vulnClock, in RFC 3339.
func ago(days int, extra time.Duration) string {
	return vulnClock.Add(-time.Duration(days)*24*time.Hour - extra).Format(time.RFC3339)
}

// A finding is overdue when it is critical and open more than 30 days, or
// high and open more than 90 days.
func TestVulnOverdueRule(t *testing.T) {
	mock := richMock()
	mock.dependabotAlerts = map[string][]github.DependabotAlert{
		"test-org/repo1": {
			{Number: 1, Severity: "critical", CreatedAt: ago(30, 0)},           // exactly 30 days
			{Number: 2, Severity: "critical", CreatedAt: ago(30, time.Second)}, // overdue
			{Number: 3, Severity: "high", CreatedAt: ago(90, 0)},               // exactly 90 days
			{Number: 4, Severity: "high", CreatedAt: ago(91, 0)},               // overdue
			{Number: 5, Severity: "medium", CreatedAt: ago(400, 0)},            // never overdue
		},
	}
	v, _ := vulnsAt(t, componentsdk.LevelAudit, mock)
	dep := v.Scanners[0]
	if dep.Scanner != "dependabot" || dep.Category != "dependencies" {
		t.Fatalf("first scanner = %s %s", dep.Scanner, dep.Category)
	}
	for name, got := range map[string]struct {
		count *int
		want  int
	}{
		"open_critical_count":    {dep.OpenCriticalCount, 2},
		"open_high_count":        {dep.OpenHighCount, 2},
		"open_medium_count":      {dep.OpenMediumCount, 1},
		"open_low_count":         {dep.OpenLowCount, 0},
		"overdue_critical_count": {dep.OverdueCriticalCount, 1},
		"overdue_high_count":     {dep.OverdueHighCount, 1},
	} {
		if got.count == nil || *got.count != got.want {
			t.Errorf("%s = %v, want %d", name, got.count, got.want)
		}
	}
	wantFlag(t, "open_critical_present", dep.OpenCriticalPresent, true)
	wantFlag(t, "overdue_present", dep.OverduePresent, true)
}

func TestVulnNotOverdueWhenEveryFindingIsRecent(t *testing.T) {
	mock := richMock()
	mock.dependabotAlerts = map[string][]github.DependabotAlert{
		"test-org/repo1": {{Number: 1, Severity: "critical", CreatedAt: ago(29, 0)}, {Number: 2, Severity: "high", CreatedAt: ago(89, 0)}},
	}
	v, _ := vulnsAt(t, componentsdk.LevelTrust, mock)
	wantFlag(t, "open_critical_present", v.Scanners[0].OpenCriticalPresent, true)
	wantFlag(t, "overdue_present", v.Scanners[0].OverduePresent, false)
	if v.Scanners[0].OpenCriticalCount != nil {
		t.Errorf("open_critical_count = %d at trust, want it left out", *v.Scanners[0].OpenCriticalCount)
	}
}

// Code scanning alerts are rated by their rule's security severity. An alert
// from a rule that is not a security query has none and is not counted.
func TestVulnCodeScanningUsesTheSecuritySeverity(t *testing.T) {
	mock := richMock()
	mock.codeAlerts = map[string][]github.CodeScanningAlert{
		"test-org/repo1": {
			{Number: 1, Severity: "error", SecuritySeverity: "high", CreatedAt: ago(100, 0)},
			{Number: 2, Severity: "error", CreatedAt: ago(100, 0)},
		},
	}
	v, _ := vulnsAt(t, componentsdk.LevelAudit, mock)
	cs := v.Scanners[1]
	if cs.Scanner != "code_scanning" || cs.OpenHighCount == nil || *cs.OpenHighCount != 1 || *cs.OpenCriticalCount != 0 || *cs.OverdueHighCount != 1 {
		t.Errorf("code scanning = %+v, want one overdue high alert", cs)
	}
}

func TestVulnSecretScanningHasNoSeverity(t *testing.T) {
	v, gaps := vulnsAt(t, componentsdk.LevelTrust, richMock())
	ss := v.Scanners[2]
	if ss.Scanner != "secret_scanning" || ss.OpenCriticalPresent != nil || ss.OverduePresent != nil {
		t.Errorf("secret scanning = %+v, want no severity values", ss)
	}
	if g := vulnGap(gaps, "/scanners/2/open_critical_present"); g == nil || g.Code != componentsdk.CodeUnsupported {
		t.Errorf("gap = %+v, want unsupported", g)
	}
	if g := vulnGap(gaps, "/scanners/2/open_critical_count"); g != nil {
		t.Errorf("a trust run has a gap on open_critical_count, which it does not write")
	}
	wantFlag(t, "enabled", ss.Enabled, true)
}

// Alert lists that could not be read leave the alert values out, with a
// gap over the repositories they cover. The coverage comes from the
// repositories' settings and stays.
func TestVulnFailedAlertListLeavesTheCountsOut(t *testing.T) {
	mock := richMock()
	mock.dependabotAlerts = map[string][]github.DependabotAlert{
		"test-org/repo1": {{Number: 1, Severity: "critical", CreatedAt: ago(1, 0)}},
	}
	mock.alertListErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, github.ErrPermissionDenied)
	v, gaps := vulnsAt(t, componentsdk.LevelAudit, mock)
	dep := v.Scanners[0]
	if dep.OpenCriticalPresent != nil || dep.OpenCriticalCount != nil {
		t.Errorf("dependabot = %+v, want the alert values left out", dep)
	}
	if g := vulnGap(gaps, "/scanners/0/open_critical_present"); g == nil || g.Code != componentsdk.CodePermissionDenied || g.Unmeasured != 2 {
		t.Errorf("gap = %+v, want permission_denied over both repositories", g)
	}
	if dep.CoveragePct.Value == nil || *dep.CoveragePct.Value != 100 {
		t.Errorf("coverage_pct = %+v, want 100 from the repositories' settings", dep.CoveragePct)
	}
}

func TestVulnAlertsNotEnabledCountAsNone(t *testing.T) {
	mock := richMock()
	mock.dependabotAlerts = nil
	mock.alertListErr = componentsdk.CodeError(componentsdk.CodeNotLicensed, github.ErrFeatureUnavailable)
	v, _ := vulnsAt(t, componentsdk.LevelAudit, mock)
	dep := v.Scanners[0]
	wantFlag(t, "open_critical_present", dep.OpenCriticalPresent, false)
	if dep.OpenCriticalCount == nil || *dep.OpenCriticalCount != 0 {
		t.Errorf("open_critical_count = %v, want 0", dep.OpenCriticalCount)
	}
}

func TestVulnAlertsAtTheCapLeaveTheCountsOut(t *testing.T) {
	mock := richMock()
	mock.alertListMore = true
	v, gaps := vulnsAt(t, componentsdk.LevelAudit, mock)
	if v.Scanners[1].OpenCriticalCount != nil {
		t.Errorf("open_critical_count = %d, want it left out", *v.Scanners[1].OpenCriticalCount)
	}
	if g := vulnGap(gaps, "/scanners/1/open_critical_count"); g == nil || g.Code != componentsdk.CodeTooLarge {
		t.Errorf("gap = %+v, want too_large", g)
	}
}

// Enabled is true when any in-scope repository has the scanner on, and
// coverage is the share that do.
func TestVulnEnabledAndCoverage(t *testing.T) {
	mock := richMock()
	v, _ := vulnsAt(t, componentsdk.LevelAudit, mock)
	for i, want := range []struct {
		enabled  bool
		coverage float64
	}{{true, 100}, {true, 50}, {true, 50}} {
		s := v.Scanners[i]
		wantFlag(t, s.Scanner+" enabled", s.Enabled, want.enabled)
		if s.CoveragePct.Value == nil || *s.CoveragePct.Value != want.coverage {
			t.Errorf("%s coverage_pct = %+v, want %v", s.Scanner, s.CoveragePct, want.coverage)
		}
		if s.ResourceCount == nil || *s.ResourceCount != 2 {
			t.Errorf("%s resource_count = %v, want 2", s.Scanner, s.ResourceCount)
		}
	}

	mock = richMock()
	mock.repositories = nil
	v, _ = vulnsAt(t, componentsdk.LevelTrust, mock)
	for _, s := range v.Scanners {
		wantFlag(t, s.Scanner+" enabled", s.Enabled, false)
		wantFlag(t, s.Scanner+" resources_present", s.ResourcesPresent, false)
		if !s.CoveragePct.Read || s.CoveragePct.Value != nil {
			t.Errorf("%s coverage_pct = %+v, want null over no repositories", s.Scanner, s.CoveragePct)
		}
	}
}

// A trust run lists code scanning and Dependabot alerts, and no secret
// scanning alerts, since vuln-scanning has no use for them.
func TestTrustRunListsNoSecretScanningAlerts(t *testing.T) {
	mock := &countingAlerts{mockGitHubClient: richMock()}
	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, CollectVulns: true}, mock)
	if _, err := c.Collect(t.Context(), componentsdk.LevelTrust); err != nil {
		t.Fatal(err)
	}
	if mock.secret != 0 || mock.code != 2 || mock.deps != 2 {
		t.Errorf("alert lists of secret scanning %d, code scanning %d, and Dependabot %d, want 0, 2, and 2", mock.secret, mock.code, mock.deps)
	}
	mock = &countingAlerts{mockGitHubClient: richMock()}
	c = NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, CollectVulns: true}, mock)
	if _, err := c.Collect(t.Context(), componentsdk.LevelAudit); err != nil {
		t.Fatal(err)
	}
	if mock.secret != 2 || mock.code != 2 || mock.deps != 2 {
		t.Errorf("audit alert lists of secret scanning %d, code scanning %d, and Dependabot %d, want 2 of each", mock.secret, mock.code, mock.deps)
	}
}

// countingAlerts counts the alert lists of each type.
type countingAlerts struct {
	*mockGitHubClient
	secret, code, deps int
}

func (m *countingAlerts) ListSecretScanningAlerts(ctx context.Context, owner, repo string) ([]github.SecretScanningAlert, bool, error) {
	m.secret++
	return m.mockGitHubClient.ListSecretScanningAlerts(ctx, owner, repo)
}

func (m *countingAlerts) ListCodeScanningAlerts(ctx context.Context, owner, repo string) ([]github.CodeScanningAlert, bool, error) {
	m.code++
	return m.mockGitHubClient.ListCodeScanningAlerts(ctx, owner, repo)
}

func (m *countingAlerts) ListDependabotAlerts(ctx context.Context, owner, repo string) ([]github.DependabotAlert, bool, error) {
	m.deps++
	return m.mockGitHubClient.ListDependabotAlerts(ctx, owner, repo)
}
