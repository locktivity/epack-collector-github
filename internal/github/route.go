package github

import (
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// TemplateRoute replaces the organization, owner, repository, login,
// environment, branch, and file path segments of a GitHub API path with
// placeholders, so the collector result's per-request rows carry no names.
func TemplateRoute(path string) string {
	segs := strings.Split(path, "/")
	if len(segs) > 2 {
		switch segs[1] {
		case "orgs":
			segs[2] = "{org}"
		case "users":
			segs[2] = "{login}"
		case "repos":
			segs = templateRepoRoute(segs)
		}
	}
	return componentsdk.TemplateRoute(strings.Join(segs, "/"))
}

func templateRepoRoute(segs []string) []string {
	segs[2] = "{owner}"
	if len(segs) > 3 {
		segs[3] = "{repo}"
	}
	switch {
	case len(segs) > 6 && segs[4] == "rules" && segs[5] == "branches":
		return append(segs[:6], "{branch}")
	case len(segs) > 5 && segs[4] == "contents":
		return append(segs[:5], "{path}")
	case len(segs) > 5 && segs[4] == "environments":
		segs[5] = "{environment}"
	}
	return segs
}
