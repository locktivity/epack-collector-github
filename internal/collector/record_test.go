//go:build record

package collector

import (
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// TestRecord records two sandboxes, GitHub organizations kept with known
// settings, to testdata/recordings/github-compliant.json and
// github-noncompliant.json for the collectortest suite. Each signs in as a
// GitHub App installed in its organization, reading the organization's login
// and the App's IDs from SANDBOX_ORG, SANDBOX_APP_ID, and
// SANDBOX_APP_INSTALLATION_ID, and the App's private key from
// GITHUB_APP_PRIVATE_KEY, and skips when any is not set. Both read the same
// variables, so record one organization at a time:
//
//	SANDBOX_ORG=... SANDBOX_APP_ID=... SANDBOX_APP_INSTALLATION_ID=... GITHUB_APP_PRIVATE_KEY="$(cat key.pem)" \
//	  go test -tags record -run 'TestRecord/^github-compliant$' -count=1 ./internal/collector/
//
// The recordings name the organization and the App by the kit's values, and
// the value of any other SANDBOX_ variable becomes a stable fake. GitHub's
// responses also carry IDs, node IDs, logins, and the App's slug, which
// resolve to the organization or a person through GitHub's API, so the test
// records again with each one found replaced by a fake, until a recording
// holds none it did not replace. recordScrubPatterns remove profile text and
// git object IDs, and nothing is written while unscrubbed finds anything.
func TestRecord(t *testing.T) {
	for _, target := range []struct {
		name   string
		config map[string]any
	}{
		{"github-compliant", map[string]any{"level": "trust"}},
		{"github-noncompliant", map[string]any{"level": "audit", "exclude_patterns": []any{"scratch-*"}}},
	} {
		t.Run(target.name, func(t *testing.T) {
			org, appID, installationID := os.Getenv("SANDBOX_ORG"), os.Getenv("SANDBOX_APP_ID"), os.Getenv("SANDBOX_APP_INSTALLATION_ID")
			privateKey := os.Getenv("GITHUB_APP_PRIVATE_KEY")
			if org == "" || appID == "" || installationID == "" || privateKey == "" {
				t.Skip("set SANDBOX_ORG, SANDBOX_APP_ID, SANDBOX_APP_INSTALLATION_ID, and GITHUB_APP_PRIVATE_KEY to record")
			}
			// Record replaces the login wherever its text appears.
			for _, host := range []string{"api.github.com", "avatars.githubusercontent.com"} {
				if strings.Contains(host, strings.ToLower(org)) {
					t.Fatal("SANDBOX_ORG is part of a GitHub host name, so replacing it would change every URL")
				}
			}
			app, err := strconv.ParseInt(appID, 10, 64)
			if err != nil {
				t.Fatal("SANDBOX_APP_ID is not a number")
			}
			installation, err := strconv.ParseInt(installationID, 10, 64)
			if err != nil {
				t.Fatal("SANDBOX_APP_INSTALLATION_ID is not a number")
			}
			config := maps.Clone(target.config)
			config["organization"], config["app_id"], config["installation_id"] = org, app, installation
			opts := collectortest.RecordOptions{
				Spec:    Spec("record", "collectortest"),
				Run:     Run,
				Config:  config,
				Secrets: map[string]string{"GITHUB_APP_PRIVATE_KEY": privateKey},
				Scrub: collectortest.ScrubRules{
					Identifiers: collectortest.EnvIdentifiers("SANDBOX_", map[string]string{
						"SANDBOX_ORG":                 kitOrg,
						"SANDBOX_APP_ID":              strconv.Itoa(kitAppID),
						"SANDBOX_APP_INSTALLATION_ID": strconv.Itoa(kitInstallationID),
					}),
					Patterns: recordScrubPatterns,
				},
			}
			report, raw := recordUntilScrubbed(t, opts)
			if report.ExitCode != 0 {
				t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
			}
			out := filepath.Join("testdata", "recordings", target.name+".json")
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(out, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("recorded %d responses", report.Responses)
		})
	}
}

// maxRecordPasses bounds the passes recordUntilScrubbed makes: the first finds
// the identifiers, the second replaces them, and a third covers an
// organization that changed between the two.
const maxRecordPasses = 3

// recordUntilScrubbed records into a temporary file until a recording holds
// no identifier tenantIdentifiers finds that the pass did not replace, then
// returns it once unscrubbed finds nothing in it.
func recordUntilScrubbed(t *testing.T, opts collectortest.RecordOptions) (collectortest.RecordReport, []byte) {
	t.Helper()
	identifiers := maps.Clone(opts.Scrub.Identifiers)
	for pass := 1; pass <= maxRecordPasses; pass++ {
		opts.Out = filepath.Join(t.TempDir(), "recording.json")
		opts.Scrub.Identifiers = identifiers
		report, err := collectortest.Record(opts)
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		sc, err := collectortest.LoadScenario(opts.Out)
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		found, err := tenantIdentifiers(sc, identifiers)
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if len(found) > 0 {
			t.Logf("pass %d found %d identifiers to replace", pass, len(found))
			maps.Copy(identifiers, found)
			continue
		}
		raw, err := os.ReadFile(opts.Out)
		if err != nil {
			t.Fatal(err)
		}
		problems, err := unscrubbed(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) > 0 {
			t.Fatalf("the recording still holds what it must not, so nothing was written:\n%s", strings.Join(problems, "\n"))
		}
		return report, raw
	}
	t.Fatalf("each of %d passes found identifiers the one before had not, so nothing was written; record again", maxRecordPasses)
	return collectortest.RecordReport{}, nil
}
