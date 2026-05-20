package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
)

// These tests pin the truncation ordering for each finding type so the
// severity-rank split (one shared map → per-type maps) stays behavior-preserving.

func TestLessCodeScanningAlert_Ordering(t *testing.T) {
	// error > warning > note (code-scanning severity vocabulary).
	errAlert := github.CodeScanningAlert{Severity: "error", CreatedAt: "2026-01-05"}
	warnAlert := github.CodeScanningAlert{Severity: "warning", CreatedAt: "2026-01-01"}
	noteAlert := github.CodeScanningAlert{Severity: "note", CreatedAt: "2026-01-01"}

	if !lessCodeScanningAlert(errAlert, warnAlert) {
		t.Error("error should sort before warning")
	}
	if lessCodeScanningAlert(warnAlert, errAlert) {
		t.Error("warning should not sort before error")
	}
	if !lessCodeScanningAlert(warnAlert, noteAlert) {
		t.Error("warning should sort before note")
	}

	// Same severity: oldest created-at first.
	older := github.CodeScanningAlert{Severity: "error", CreatedAt: "2026-01-01"}
	newer := github.CodeScanningAlert{Severity: "error", CreatedAt: "2026-01-02"}
	if !lessCodeScanningAlert(older, newer) {
		t.Error("same severity: older created-at should sort first")
	}
}

func TestLessDependabotAlert_Ordering(t *testing.T) {
	// critical > high > medium > low (Dependabot severity vocabulary).
	order := []string{"critical", "high", "medium", "low"}
	for i := 0; i+1 < len(order); i++ {
		hi := github.DependabotAlert{Severity: order[i]}
		lo := github.DependabotAlert{Severity: order[i+1]}
		if !lessDependabotAlert(hi, lo) {
			t.Errorf("%s should sort before %s", order[i], order[i+1])
		}
		if lessDependabotAlert(lo, hi) {
			t.Errorf("%s should not sort before %s", order[i+1], order[i])
		}
	}

	// Same severity: oldest created-at first.
	older := github.DependabotAlert{Severity: "high", CreatedAt: "2026-01-01"}
	newer := github.DependabotAlert{Severity: "high", CreatedAt: "2026-01-02"}
	if !lessDependabotAlert(older, newer) {
		t.Error("same severity: older created-at should sort first")
	}
}

func TestLessSecretScanningAlert_OrderingByCreatedAt(t *testing.T) {
	older := github.SecretScanningAlert{CreatedAt: "2026-01-01"}
	newer := github.SecretScanningAlert{CreatedAt: "2026-01-02"}
	if !lessSecretScanningAlert(older, newer) {
		t.Error("older created-at should sort first")
	}
	if lessSecretScanningAlert(newer, older) {
		t.Error("newer created-at should not sort first")
	}
}
