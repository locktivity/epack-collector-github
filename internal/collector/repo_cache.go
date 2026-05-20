package collector

import "github.com/locktivity/epack-collector-github/internal/github"

// repoCache holds the included repositories and their per-repo REST security
// settings, captured during the repository scan so the audit/internal surfaces
// can reuse them without re-fetching.
type repoCache struct {
	included []github.Repository
	settings map[string]*github.SecuritySettings // keyed by "owner/repo"
}

// add records an included repository.
func (rc *repoCache) add(repo github.Repository) {
	rc.included = append(rc.included, repo)
}

// recordSettings caches a repo's REST security settings for the audit-level
// SecurityFeatures surface.
func (rc *repoCache) recordSettings(owner, name string, settings *github.SecuritySettings) {
	if rc.settings == nil {
		rc.settings = make(map[string]*github.SecuritySettings)
	}
	rc.settings[owner+"/"+name] = settings
}

// settingsFor returns the cached settings for a repo, or nil if none recorded.
func (rc *repoCache) settingsFor(owner, name string) *github.SecuritySettings {
	return rc.settings[owner+"/"+name]
}
