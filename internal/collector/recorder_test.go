package collector

import (
	"context"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// collectRecorded runs Collect at level with a recorder. It returns the
// posture and the recorder, so a test can read the run's gaps and warnings.
func collectRecorded(t *testing.T, config Config, client github.GitHubClient, level componentsdk.Level) (*OrgPosture, *componentsdk.Recorder) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	config.Recorder = rec
	posture, err := NewWithClient(config, client).Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture, rec
}

// warningWith returns the first run warning rec holds whose message contains
// text, or nil.
func warningWith(rec *componentsdk.Recorder, text string) *componentsdk.RunWarning {
	for _, w := range rec.Warnings() {
		if strings.Contains(w.Message, text) {
			return &w
		}
	}
	return nil
}

// gapOf returns the gap rec holds at pointer in the detailed artifact, or nil.
func gapOf(rec *componentsdk.Recorder, pointer string) *componentsdk.Gap {
	for _, g := range rec.Gaps() {
		if g.Path == DetailedPath && g.Pointer == pointer {
			return &g
		}
	}
	return nil
}
