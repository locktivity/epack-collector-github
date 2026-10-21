package collector

import "github.com/locktivity/epack-collector-github/internal/github"

// repoCache holds the included repositories, their per-repo REST security
// settings, and their effective branch protection, captured during the trust
// pass so the audit/internal surfaces can reuse them without re-fetching.
type repoCache struct {
	included    []github.Repository
	settings    map[string]*github.SecuritySettings // keyed by "owner/repo"
	settingsErr map[string]error                    // keyed by "owner/repo"
	protections map[string]*repoProtection          // keyed by "owner/repo"
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

// recordSettingsErr caches why a repo's REST security settings could not be
// read.
func (rc *repoCache) recordSettingsErr(owner, name string, err error) {
	if rc.settingsErr == nil {
		rc.settingsErr = make(map[string]error)
	}
	rc.settingsErr[owner+"/"+name] = err
}

// recordProtection caches a repo's effective default-branch protection.
func (rc *repoCache) recordProtection(owner, name string, p *repoProtection) {
	if rc.protections == nil {
		rc.protections = make(map[string]*repoProtection)
	}
	rc.protections[owner+"/"+name] = p
}

// protectionFor returns a repo's effective protection. A repo with none
// recorded has unknown ruleset rules.
func (rc *repoCache) protectionFor(repo github.Repository) *repoProtection {
	if p, ok := rc.protections[repo.Owner.Login+"/"+repo.Name]; ok {
		return p
	}
	return evaluateProtection(repo.DefaultBranchRef.BranchProtectionRule, nil, false, nil)
}

// protectionList returns every included repo's effective protection, in scan
// order.
func (rc *repoCache) protectionList() []*repoProtection {
	out := make([]*repoProtection, 0, len(rc.included))
	for _, r := range rc.included {
		out = append(out, rc.protectionFor(r))
	}
	return out
}
