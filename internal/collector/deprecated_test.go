package collector

import (
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// A collect list that leaves out access-posture or vuln-scanning leaves out
// the deprecated block that moved to it, with a not_shared gap. The other
// block stays.
func TestCollectLeavesOutTheDeprecatedBlocksMovedToAKindLeftOut(t *testing.T) {
	names := map[string]string{"access-posture": "org_security", "vuln-scanning": "security_features"}
	full := emitted(t, runKit(t, kitConfig(), kitSecrets(), kitResponses()), NormalizedPath)
	for _, block := range names {
		if full[block] == nil {
			t.Fatalf("vcs-posture = %v, want %s with every kind collected", full, block)
		}
	}

	for left := range names {
		t.Run(left, func(t *testing.T) {
			config := kitConfig()
			config["collect"] = []any{"vcs-posture", "details", other(left)}
			res := runKit(t, config, kitSecrets(), kitResponses())
			if res.ExitCode != 0 {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			doc := emitted(t, res, NormalizedPath)
			if got, ok := doc[names[left]]; ok {
				t.Errorf("vcs-posture has %s = %v, which moved to %s", names[left], got, left)
			}
			if doc[names[other(left)]] == nil {
				t.Errorf("vcs-posture = %v, want %s, which moved to a kind collected", doc, names[other(left)])
			}
			if g := gapAt(res, NormalizedPath, "/"+names[left]); g == nil || g.Code != componentsdk.CodeNotShared {
				t.Errorf("gap at /%s = %+v, want not_shared", names[left], g)
			}
		})
	}
}

// other is the moved kind that isn't kind.
func other(kind string) string {
	if kind == "access-posture" {
		return "vuln-scanning"
	}
	return "access-posture"
}
