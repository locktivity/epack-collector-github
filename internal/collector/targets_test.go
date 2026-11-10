package collector

import (
	"maps"
	"net/http"
	"reflect"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitOrgTarget is the organization target of a run with the kit's config.
// count is nil at trust, which writes no count.
func kitOrgTarget(count *int) componentsdk.ResultTarget {
	return componentsdk.ResultTarget{
		Kind:      componentsdk.TargetOrganization,
		ChosenBy:  componentsdk.ChosenByConfig,
		ConfigKey: "organization",
		At:        &componentsdk.Location{Schema: NormalizedSchema, Path: NormalizedPath, Pointer: "/organization"},
		Count:     count,
		Complete:  ptr(true),
	}
}

// kitRepoTarget is the repository target of an audit run with the kit's
// config, which excludes sandbox-*.
func kitRepoTarget(count int, complete bool) componentsdk.ResultTarget {
	at := func(pointer string) *componentsdk.Location {
		return &componentsdk.Location{Path: DetailedPath, Pointer: pointer}
	}
	return componentsdk.ResultTarget{
		Kind:      componentsdk.TargetRepository,
		ChosenBy:  componentsdk.ChosenByFilter,
		ConfigKey: "exclude_patterns",
		At:        at("/repositories/per_repo"),
		Name:      []string{"/name"},
		Found:     at("/scope/repository_count"),
		Assessed:  at("/scope/included_repository_count"),
		Coverage:  &componentsdk.Location{Schema: NormalizedSchema, Path: NormalizedPath, Pointer: "/repo_coverage_pct"},
		Include:   at("/scope/include_patterns"),
		Exclude:   at("/scope/exclude_patterns"),
		Count:     ptr(count),
		Complete:  ptr(complete),
	}
}

func kitConfigWith(overrides map[string]any) map[string]any {
	config := kitConfig()
	maps.Copy(config, overrides)
	for key, value := range overrides {
		if value == nil {
			delete(config, key)
		}
	}
	return config
}

// targetsOf returns the run's organization and repository targets, and fails
// the test unless the result declares those two alone and the artifacts bear
// them out.
func targetsOf(t *testing.T, res componentsdk.InProcessResult) (org, repos componentsdk.ResultTarget) {
	t.Helper()
	if res.Result == nil {
		t.Fatalf("no collector result; exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, f := range res.Result.Checks {
		if f.Check == componentsdk.CheckTargets {
			t.Errorf("targets check: %s %s %s", f.Path, f.Pointer, f.Message)
		}
	}
	got := res.Result.Targets
	if len(got) != 2 || got[0].Kind != componentsdk.TargetOrganization || got[1].Kind != componentsdk.TargetRepository {
		t.Fatalf("targets = %+v, want the organization and its repositories", got)
	}
	return got[0], got[1]
}

func checkTarget(t *testing.T, got, want componentsdk.ResultTarget) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s target:\n got  %s\n want %s", want.Kind, kitJSON(got), kitJSON(want))
	}
}

func TestAnAuditRunDeclaresTheOrganizationAndTheRepositoriesItAssessed(t *testing.T) {
	res := runKit(t, kitConfigWith(map[string]any{"level": "audit"}), kitSecrets(), kitResponses())
	org, repos := targetsOf(t, res)
	checkTarget(t, org, kitOrgTarget(ptr(1)))
	checkTarget(t, repos, kitRepoTarget(4, true))
}

// The detailed artifact is audit-level as a whole, so a trust run keeps the
// organization, from the normalized artifact, and the repositories' coverage
// alone.
func TestATrustRunKeepsOnlyTheNormalizedTargetValues(t *testing.T) {
	res := runKit(t, kitConfigWith(map[string]any{"level": "trust"}), kitSecrets(), kitResponses())
	org, repos := targetsOf(t, res)
	checkTarget(t, org, kitOrgTarget(nil))
	checkTarget(t, repos, componentsdk.ResultTarget{
		Kind:      componentsdk.TargetRepository,
		ChosenBy:  componentsdk.ChosenByFilter,
		ConfigKey: "exclude_patterns",
		Coverage:  &componentsdk.Location{Schema: NormalizedSchema, Path: NormalizedPath, Pointer: "/repo_coverage_pct"},
	})
}

func TestARepositoryWhoseProtectionReadFailsLeavesTheRepositoriesIncomplete(t *testing.T) {
	responses := replaceResponse(kitResponses(), collectortest.Response{
		URL:    kitRepoURL("classic-only", "/rules/branches/main?per_page=100"),
		Status: http.StatusBadGateway,
		Body:   `{"message":"Server Error"}`,
	})
	res := runKit(t, kitConfigWith(map[string]any{"level": "audit"}), kitSecrets(), responses)
	org, repos := targetsOf(t, res)
	checkTarget(t, org, kitOrgTarget(ptr(1)))
	checkTarget(t, repos, kitRepoTarget(4, false))
}

func TestRepositoriesSayHowTheConfigOrTheAppNarrowedThem(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]any
		responses []collectortest.Response
		how       componentsdk.TargetChoice
		key       string
		count     int
	}{
		{
			name:   "the default patterns",
			config: map[string]any{"exclude_patterns": nil},
			how:    componentsdk.ChosenByDiscovery,
			count:  5,
		},
		{
			name:   "the default include pattern written out",
			config: map[string]any{"include_patterns": []any{"*"}, "exclude_patterns": []any{}},
			how:    componentsdk.ChosenByDiscovery,
			count:  5,
		},
		{
			name:   "include patterns",
			config: map[string]any{"include_patterns": []any{"classic-*"}, "exclude_patterns": nil},
			how:    componentsdk.ChosenByFilter,
			key:    "include_patterns",
			count:  2,
		},
		{
			name:   "include and exclude patterns",
			config: map[string]any{"include_patterns": []any{"classic-*"}},
			how:    componentsdk.ChosenByFilter,
			key:    "exclude_patterns",
			count:  2,
		},
		{
			name:      "an App on selected repositories",
			config:    map[string]any{"exclude_patterns": nil},
			responses: kitSelectedResponses(ptr(5)),
			how:       componentsdk.ChosenByGrant,
			count:     4,
		},
		{
			name:      "an App on selected repositories, narrowed by patterns",
			config:    map[string]any{"exclude_patterns": []any{"classic-*"}},
			responses: kitSelectedResponses(ptr(5)),
			how:       componentsdk.ChosenByGrantFilter,
			key:       "exclude_patterns",
			count:     2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses := tt.responses
			if responses == nil {
				responses = kitResponses()
			}
			tt.config["level"] = "audit"
			_, repos := targetsOf(t, runKit(t, kitConfigWith(tt.config), kitSecrets(), responses))
			if repos.ChosenBy != tt.how || repos.ConfigKey != tt.key {
				t.Errorf("chosen_by = %q config_key = %q, want %q and %q", repos.ChosenBy, repos.ConfigKey, tt.how, tt.key)
			}
			if repos.Count == nil || *repos.Count != tt.count {
				t.Errorf("count = %s, want %d", kitJSON(repos.Count), tt.count)
			}
		})
	}
}

// A repository list cut at ReposCap holds fewer repositories than the run
// assessed, so the repositories are not complete. No kit scenario reaches
// the cap, which takes ReposCap+1 repositories and their calls, so this run
// emits a posture cut short by hand.
func TestRepositoriesCutAtTheCapAreIncomplete(t *testing.T) {
	run := func(ctx componentsdk.CollectorContext) error {
		posture := NewOrgPosture(kitOrg)
		posture.Scope = Scope{
			IncludePatterns:         []string{DefaultIncludePattern},
			ExcludePatterns:         []string{},
			RepositoryCount:         ptr(2),
			IncludedRepositoryCount: ptr(2),
		}
		posture.Repositories = &Repositories{
			TotalCount:       2,
			PrivateCount:     2,
			PerRepo:          []RepoRow{{Name: kitOrg + "/kept", Visibility: "PRIVATE"}},
			Truncated:        true,
			TruncatedDropped: 1,
		}
		posture.declareTargets(componentsdk.Records(ctx))
		return ctx.Emit(posture.Artifacts())
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), run, componentsdk.InProcessOptions{Config: map[string]any{"level": "audit"}})
	_, repos := targetsOf(t, res)
	if repos.Count == nil || *repos.Count != 1 || repos.Complete == nil || *repos.Complete {
		t.Errorf("count = %s complete = %s, want 1 repository and an incomplete set", kitJSON(repos.Count), kitJSON(repos.Complete))
	}
}
