package collector

import (
	"slices"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// declareTargets declares what the run was pointed at: the organization the
// config names, and the repositories in it the run assessed.
func (o *OrgPosture) declareTargets(rec *componentsdk.Recorder) {
	rec.Targets(componentsdk.TargetOrganization, componentsdk.Location{Path: NormalizedPath, Pointer: "/organization"}).
		ChosenBy(componentsdk.ChosenByConfig, "organization")
	how, key := o.Scope.repositoryChoice()
	rec.Targets(componentsdk.TargetRepository, detailed("/repositories/per_repo"), "/name").
		ChosenBy(how, key).
		Found(detailed("/scope/repository_count")).
		Assessed(detailed("/scope/included_repository_count")).
		Coverage(componentsdk.Location{Path: NormalizedPath, Pointer: "/repo_coverage_pct"}).
		Patterns(detailed("/scope/include_patterns"), detailed("/scope/exclude_patterns"))
}

// repositoryChoice says how the run chose its repositories, and the config
// key that narrowed them. Patterns other than the default narrow them. A
// GitHub App installed on selected repositories was given only some, so the
// organization may have others the run never saw.
func (s Scope) repositoryChoice() (componentsdk.TargetChoice, string) {
	var key string
	switch {
	case len(s.ExcludePatterns) > 0:
		key = "exclude_patterns"
	case !slices.Equal(s.IncludePatterns, []string{DefaultIncludePattern}):
		key = "include_patterns"
	}
	selected := s.RepositorySelection != nil && *s.RepositorySelection == github.RepositorySelectionSelected
	switch {
	case selected && key != "":
		return componentsdk.ChosenByGrantFilter, key
	case selected:
		return componentsdk.ChosenByGrant, ""
	case key != "":
		return componentsdk.ChosenByFilter, key
	}
	return componentsdk.ChosenByDiscovery, ""
}
