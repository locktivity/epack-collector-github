package collector

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitOrg            = "test-org"
	kitAppID          = 123456
	kitInstallationID = 78901234

	kitAPI     = "https://api.github.com"
	kitGraphQL = kitAPI + "/graphql"
	kitToken   = "ghs_kitinstallationtoken0123456789"
)

var kitClock = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// kitRepos are the fixture organization's repositories in the order GitHub
// lists them. old-archive is archived and sandbox-test matches the exclude
// pattern, so four are in scope.
var kitRepos = []string{"repo-ruleset", "org-ruleset", "old-archive", "classic-only", "classic-and-org", "sandbox-test"}

// kitIncluded are the in-scope repositories, in scan order.
var kitIncluded = []string{"repo-ruleset", "org-ruleset", "classic-only", "classic-and-org"}

var (
	kitKeyOnce sync.Once
	kitKeyPEM  string
)

// kitPrivateKey is a GitHub App key generated for the test run, so no key is
// kept in the repository.
func kitPrivateKey() string {
	kitKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		kitKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	})
	return kitKeyPEM
}

func kitJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// kitTestdata reads a ruleset fixture shared with the ruleset tests.
func kitTestdata(name string) string {
	raw, err := os.ReadFile(filepath.Join("testdata", "rulesets", name))
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// kitRuleset returns a ruleset fixture with its bypass list visible.
func kitRuleset(name string, bypass []any) string {
	var rs map[string]any
	if err := json.Unmarshal([]byte(kitTestdata(name)), &rs); err != nil {
		panic(err)
	}
	rs["bypass_actors"] = bypass
	return kitJSON(rs)
}

func kitOrgRuleset() string {
	return kitRuleset("ruleset_2001.json", []any{
		map[string]any{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"},
	})
}

func kitRepoURL(repo, rest string) string {
	return fmt.Sprintf("%s/repos/%s/%s%s", kitAPI, kitOrg, repo, rest)
}

func kitOrgURL(rest string) string {
	return fmt.Sprintf("%s/orgs/%s%s", kitAPI, kitOrg, rest)
}

// kitTokenResponse answers the GitHub App's installation token exchange.
func kitTokenResponse() collectortest.Response {
	return collectortest.Response{
		Method: http.MethodPost,
		URL:    fmt.Sprintf("%s/app/installations/%d/access_tokens", kitAPI, kitInstallationID),
		Status: http.StatusCreated,
		Body: kitJSON(map[string]any{
			"token":      kitToken,
			"expires_at": "2099-01-01T00:00:00Z",
			"permissions": map[string]any{
				"administration": "read", "contents": "read", "members": "read", "metadata": "read",
			},
		}),
	}
}

// kitOrgResponse answers both the sign-in and the org settings read.
func kitOrgResponse(twoFactor bool) collectortest.Response {
	return collectortest.Response{URL: kitOrgURL(""), Body: kitJSON(map[string]any{
		"login":                           kitOrg,
		"two_factor_requirement_enabled":  twoFactor,
		"default_repository_permission":   "read",
		"members_can_create_repositories": false,
	})}
}

func kitRepoNode(name, visibility string, archived, vulnAlerts bool, classic map[string]any) map[string]any {
	return map[string]any{
		"name":                          name,
		"owner":                         map[string]any{"login": kitOrg},
		"isArchived":                    archived,
		"isTemplate":                    false,
		"visibility":                    visibility,
		"defaultBranchRef":              map[string]any{"name": "main", "branchProtectionRule": classic},
		"hasVulnerabilityAlertsEnabled": vulnAlerts,
		"createdAt":                     "2025-01-01T00:00:00Z",
		"updatedAt":                     "2026-09-01T00:00:00Z",
		"pushedAt":                      "2026-10-01T00:00:00Z",
		"diskUsage":                     2048,
		"stargazerCount":                3,
		"description":                   "Fixture repository " + name,
		"primaryLanguage":               map[string]any{"name": "Go"},
		"licenseInfo":                   map[string]any{"spdxId": "Apache-2.0"},
		"repositoryTopics":              map[string]any{"nodes": []any{map[string]any{"topic": map[string]any{"name": "security"}}}},
	}
}

func kitRepoPage(nodes []any, next string) string {
	return kitJSON(map[string]any{"data": map[string]any{"organization": map[string]any{
		"repositories": map[string]any{
			"nodes":    nodes,
			"pageInfo": map[string]any{"hasNextPage": next != "", "endCursor": next},
		},
	}}})
}

func kitRepositoryPages() []collectortest.Response {
	classicOnly := map[string]any{
		"requiresApprovingReviews": true, "requiredApprovingReviewCount": 2, "dismissesStaleReviews": true,
		"requiresCodeOwnerReviews": false, "requiresStatusChecks": true, "requiresCommitSignatures": false,
		"isAdminEnforced": true, "requiresLinearHistory": false, "allowsForcePushes": false,
		"allowsDeletions": false, "requiresConversationResolution": true,
	}
	classicAndOrg := map[string]any{
		"requiresApprovingReviews": true, "requiredApprovingReviewCount": 2, "dismissesStaleReviews": false,
		"requiresCodeOwnerReviews": false, "requiresStatusChecks": true, "requiresCommitSignatures": false,
		"isAdminEnforced": true, "requiresLinearHistory": false, "allowsForcePushes": false,
		"allowsDeletions": false, "requiresConversationResolution": false,
	}
	page1 := []any{
		kitRepoNode("repo-ruleset", "PRIVATE", false, true, nil),
		kitRepoNode("org-ruleset", "PUBLIC", false, true, nil),
		kitRepoNode("old-archive", "PRIVATE", true, false, nil),
	}
	page2 := []any{
		kitRepoNode("classic-only", "INTERNAL", false, false, classicOnly),
		kitRepoNode("classic-and-org", "PRIVATE", false, true, classicAndOrg),
		kitRepoNode("sandbox-test", "PRIVATE", false, false, nil),
	}
	return []collectortest.Response{
		{Operation: "github.repositories.list", Method: http.MethodPost, URL: kitGraphQL, Body: kitRepoPage(page1, "page-2"), Times: 1},
		{Operation: "github.repositories.list", Method: http.MethodPost, URL: kitGraphQL, Body: kitRepoPage(page2, "")},
	}
}

func kitSecuritySettings(secret, push, dependabot string) string {
	return kitJSON(map[string]any{
		"name": "fixture",
		"security_and_analysis": map[string]any{
			"secret_scanning":                 map[string]any{"status": secret},
			"secret_scanning_push_protection": map[string]any{"status": push},
			"dependabot_security_updates":     map[string]any{"status": dependabot},
		},
	})
}

const (
	kitAdvancedSecurityOff = `{"message":"Advanced Security must be enabled for this repository to use code scanning."}`
	kitSecretScanningOff   = `{"message":"Secret scanning is disabled on this repository."}`
	kitNotFound            = `{"message":"Not Found"}`
)

func kitNotFoundResponse(url string) collectortest.Response {
	return collectortest.Response{URL: url, Status: http.StatusNotFound, Body: kitNotFound}
}

// kitTrustResponses answer the calls a trust-level run makes.
func kitTrustResponses() []collectortest.Response {
	responses := []collectortest.Response{kitTokenResponse(), kitOrgResponse(true)}
	responses = append(responses, kitRepositoryPages()...)

	orgRulesetRules := kitTestdata("rules_org-ruleset.json")
	responses = append(responses,
		collectortest.Response{URL: kitRepoURL("repo-ruleset", "/rules/branches/main?per_page=100"), Body: kitTestdata("rules_repo-ruleset.json")},
		collectortest.Response{URL: kitRepoURL("org-ruleset", "/rules/branches/main?per_page=100"), Body: orgRulesetRules},
		collectortest.Response{URL: kitRepoURL("classic-only", "/rules/branches/main?per_page=100"), Body: `[]`},
		collectortest.Response{URL: kitRepoURL("classic-and-org", "/rules/branches/main?per_page=100"), Body: orgRulesetRules},
		collectortest.Response{URL: kitRepoURL("repo-ruleset", "/rulesets/1001?includes_parents=true"), Body: kitRuleset("ruleset_1001.json", []any{
			map[string]any{"actor_id": 1234, "actor_type": "Integration", "bypass_mode": "always"},
		})},
		collectortest.Response{URL: kitRepoURL("org-ruleset", "/rulesets/2001?includes_parents=true"), Body: kitOrgRuleset()},
		// The collector reads an organization ruleset through the first
		// repository it finds it on, which a failed rules read can change.
		collectortest.Response{URL: kitRepoURL("classic-and-org", "/rulesets/2001?includes_parents=true"), Body: kitOrgRuleset()},

		collectortest.Response{URL: kitRepoURL("repo-ruleset", ""), Body: kitSecuritySettings("enabled", "enabled", "enabled")},
		collectortest.Response{URL: kitRepoURL("repo-ruleset", "/code-scanning/default-setup"), Body: `{"state":"configured"}`},
		collectortest.Response{URL: kitRepoURL("org-ruleset", ""), Body: kitSecuritySettings("enabled", "disabled", "disabled")},
		collectortest.Response{URL: kitRepoURL("org-ruleset", "/code-scanning/default-setup"), Body: `{"state":"not-configured"}`},
		collectortest.Response{URL: kitRepoURL("org-ruleset", "/code-scanning/analyses?per_page=1"), Body: `[{"ref":"refs/heads/main","tool":{"name":"CodeQL"}}]`},
		collectortest.Response{URL: kitRepoURL("classic-only", ""), Body: kitSecuritySettings("disabled", "disabled", "disabled")},
		collectortest.Response{URL: kitRepoURL("classic-only", "/code-scanning/default-setup"), Status: http.StatusForbidden, Body: kitAdvancedSecurityOff},
		collectortest.Response{URL: kitRepoURL("classic-and-org", ""), Body: kitSecuritySettings("disabled", "disabled", "enabled")},
		kitNotFoundResponse(kitRepoURL("classic-and-org", "/code-scanning/default-setup")),
		kitNotFoundResponse(kitRepoURL("classic-and-org", "/code-scanning/analyses?per_page=1")),
	)
	return responses
}

func kitAlertListURL(repo, kind string) string {
	query := "?state=open&per_page=100"
	if kind == "secret-scanning" {
		query += "&hide_secret=true"
	}
	return kitRepoURL(repo, "/"+kind+"/alerts"+query)
}

// kitDependabotNextPage is the second page of repo-ruleset's Dependabot
// alerts, served under the repository's numeric ID.
const kitDependabotNextPage = kitAPI + "/repositories/1/dependabot/alerts?state=open&per_page=100&after=Y3Vyc29yOjg"

// kitNextPage is the Link header of a first page whose second page GitHub
// serves at path, as it does with the organization's numeric ID.
func kitNextPage(path string) http.Header {
	next := kitAPI + path + "?per_page=100&page=2"
	return http.Header{"Link": []string{fmt.Sprintf(`<%s>; rel="next", <%s>; rel="last"`, next, next)}}
}

// kitAuditResponses answer the calls audit adds to trust.
func kitAuditResponses() []collectortest.Response {
	codeownersBody := func(size int) string {
		return kitJSON(map[string]any{"type": "file", "encoding": "base64", "size": size, "content": "KiBAdGVzdC1vcmcvc2VjdXJpdHkK\n"})
	}
	environments := kitJSON(map[string]any{"total_count": 2, "environments": []any{
		map[string]any{
			"name": "production", "created_at": "2026-02-01T00:00:00Z", "updated_at": "2026-02-02T00:00:00Z",
			"can_admins_bypass": true,
			"protection_rules": []any{
				map[string]any{"type": "required_reviewers", "prevent_self_review": true, "reviewers": []any{
					map[string]any{"type": "Team", "reviewer": map[string]any{"slug": "release-approvers", "name": "Release Approvers"}},
					map[string]any{"type": "User", "reviewer": map[string]any{"login": "alice"}},
				}},
				map[string]any{"type": "wait_timer", "wait_timer": 30},
			},
			"deployment_branch_policy": map[string]any{"protected_branches": true, "custom_branch_policies": false},
		},
		map[string]any{
			"name":                     "staging",
			"deployment_branch_policy": map[string]any{"protected_branches": false, "custom_branch_policies": true},
		},
	}})
	noEnvironments := `{"total_count":0,"environments":[]}`
	noRunners := `{"total_count":0,"runners":[]}`

	responses := []collectortest.Response{
		{URL: kitAlertListURL("repo-ruleset", "secret-scanning"), Body: kitJSON([]any{map[string]any{
			"number": 3, "secret_type": "aws_access_key_id", "state": "open", "created_at": "2026-05-01T00:00:00Z",
		}})},
		{URL: kitAlertListURL("repo-ruleset", "code-scanning"), Body: kitJSON([]any{map[string]any{
			"number": 4, "state": "open", "created_at": "2026-05-02T00:00:00Z",
			"rule":                 map[string]any{"id": "go/sql-injection", "severity": "error"},
			"most_recent_instance": map[string]any{"location": map[string]any{"path": "internal/db/query.go"}},
		}})},
		// Dependabot pages by cursor, so its Link header has no last page.
		{
			URL:    kitAlertListURL("repo-ruleset", "dependabot"),
			Header: http.Header{"Link": []string{`<` + kitDependabotNextPage + `>; rel="next"`}},
			Body: kitJSON([]any{map[string]any{
				"number": 8, "state": "open", "created_at": "2026-06-01T00:00:00Z",
				"security_vulnerability": map[string]any{"severity": "low", "package": map[string]any{"ecosystem": "npm", "name": "left-pad"}},
			}}),
		},
		{URL: kitDependabotNextPage, Body: kitJSON([]any{map[string]any{
			"number": 9, "state": "open", "created_at": "2026-06-02T00:00:00Z",
			"security_vulnerability": map[string]any{"severity": "medium", "package": map[string]any{"ecosystem": "npm", "name": "lodash"}},
		}})},
		{URL: kitAlertListURL("org-ruleset", "secret-scanning"), Body: `[]`},
		{URL: kitAlertListURL("org-ruleset", "code-scanning"), Body: kitJSON([]any{map[string]any{
			"number": 1, "state": "open", "created_at": "2026-04-02T00:00:00Z",
			"rule": map[string]any{"id": "js/xss", "severity": "warning"},
		}})},
		kitNotFoundResponse(kitAlertListURL("org-ruleset", "dependabot")),
		{URL: kitAlertListURL("classic-only", "secret-scanning"), Status: http.StatusForbidden, Body: kitSecretScanningOff},
		{URL: kitAlertListURL("classic-only", "code-scanning"), Status: http.StatusForbidden, Body: kitAdvancedSecurityOff},
		{URL: kitAlertListURL("classic-only", "dependabot"), Body: kitJSON([]any{map[string]any{
			"number": 7, "state": "open", "created_at": "2026-03-03T00:00:00Z",
			"security_advisory":      map[string]any{"cve_id": "CVE-2026-0001"},
			"security_vulnerability": map[string]any{"severity": "high", "package": map[string]any{"ecosystem": "go", "name": "golang.org/x/net"}},
		}})},
		{URL: kitAlertListURL("classic-and-org", "secret-scanning"), Body: `[]`},
		{URL: kitAlertListURL("classic-and-org", "code-scanning"), Body: `[]`},
		{URL: kitAlertListURL("classic-and-org", "dependabot"), Body: `[]`},

		{URL: kitRepoURL("repo-ruleset", "/contents/.github/CODEOWNERS"), Body: codeownersBody(codeownersMaxBytesForKit)},
		kitNotFoundResponse(kitRepoURL("org-ruleset", "/contents/.github/CODEOWNERS")),
		kitNotFoundResponse(kitRepoURL("org-ruleset", "/contents/CODEOWNERS")),
		{URL: kitRepoURL("org-ruleset", "/contents/docs/CODEOWNERS"), Body: codeownersBody(22)},
		kitNotFoundResponse(kitRepoURL("classic-only", "/contents/.github/CODEOWNERS")),
		kitNotFoundResponse(kitRepoURL("classic-only", "/contents/CODEOWNERS")),
		kitNotFoundResponse(kitRepoURL("classic-only", "/contents/docs/CODEOWNERS")),
		{URL: kitRepoURL("classic-and-org", "/contents/.github/CODEOWNERS"), Body: codeownersBody(22)},

		{URL: kitOrgURL("/hooks?per_page=100"), Body: kitJSON([]any{map[string]any{
			"id": 1, "active": true, "events": []any{"push"},
			"config":        map[string]any{"content_type": "json", "url": "https://hooks.example.com/github?secret=x"},
			"last_response": map[string]any{"code": 200, "status": "active"},
		}})},
		{URL: kitRepoURL("repo-ruleset", "/hooks?per_page=100"), Body: kitJSON([]any{map[string]any{
			"id": 2, "active": true, "events": []any{"pull_request"},
			"config": map[string]any{"content_type": "json", "url": "https://ci.example.com/hook"},
		}})},
		{URL: kitRepoURL("org-ruleset", "/hooks?per_page=100"), Body: `[]`},
		{URL: kitRepoURL("classic-only", "/hooks?per_page=100"), Body: `[]`},
		{URL: kitRepoURL("classic-and-org", "/hooks?per_page=100"), Body: `[]`},

		{URL: kitRepoURL("repo-ruleset", "/keys?per_page=100"), Body: kitJSON([]any{map[string]any{
			"id": 3, "title": "deploy", "read_only": false, "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyOne", "created_at": "2026-01-05T00:00:00Z",
		}})},
		{URL: kitRepoURL("org-ruleset", "/keys?per_page=100"), Body: `[]`},
		{URL: kitRepoURL("classic-only", "/keys?per_page=100"), Body: kitJSON([]any{map[string]any{
			"id": 4, "title": "read-only mirror", "read_only": true, "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyTwo",
		}})},
		{URL: kitRepoURL("classic-and-org", "/keys?per_page=100"), Body: `[]`},

		{URL: kitOrgURL("/actions/runners?per_page=100"), Header: kitNextPage("/organizations/1/actions/runners"), Body: kitJSON(map[string]any{"total_count": 2, "runners": []any{
			map[string]any{"id": 10, "name": "runner-1", "os": "linux", "status": "online", "busy": false, "labels": []any{map[string]any{"name": "self-hosted"}}},
		}})},
		{URL: kitAPI + "/organizations/1/actions/runners?per_page=100&page=2", Body: kitJSON(map[string]any{"total_count": 2, "runners": []any{
			map[string]any{"id": 12, "name": "runner-2", "os": "windows", "status": "online", "busy": true, "labels": []any{map[string]any{"name": "self-hosted"}, map[string]any{"name": "windows"}}},
		}})},
		{URL: kitOrgURL("/actions/secrets?per_page=100"), Header: kitNextPage("/organizations/1/actions/secrets"), Body: `{"total_count":2,"secrets":[{"name":"DEPLOY_TOKEN"}]}`},
		{URL: kitAPI + "/organizations/1/actions/secrets?per_page=100&page=2", Body: `{"total_count":2,"secrets":[{"name":"NPM_TOKEN"}]}`},
		{URL: kitRepoURL("repo-ruleset", "/actions/runners?per_page=100"), Body: kitJSON(map[string]any{"total_count": 1, "runners": []any{
			map[string]any{"id": 11, "name": "repo-runner", "os": "linux", "status": "offline", "busy": false, "labels": []any{}},
		}})},
		{URL: kitRepoURL("org-ruleset", "/actions/runners?per_page=100"), Body: noRunners},
		{URL: kitRepoURL("classic-only", "/actions/runners?per_page=100"), Body: noRunners},
		{URL: kitRepoURL("classic-and-org", "/actions/runners?per_page=100"), Body: noRunners},

		{URL: kitRepoURL("repo-ruleset", "/environments?per_page=100&page=1"), Body: environments},
		{URL: kitRepoURL("org-ruleset", "/environments?per_page=100&page=1"), Body: noEnvironments},
		{URL: kitRepoURL("classic-only", "/environments?per_page=100&page=1"), Body: noEnvironments},
		{URL: kitRepoURL("classic-and-org", "/environments?per_page=100&page=1"), Body: noEnvironments},
		{URL: kitRepoURL("repo-ruleset", "/environments/staging/deployment-branch-policies?per_page=100"), Body: `{"total_count":1,"branch_policies":[{"id":1,"name":"release/*","type":"branch"}]}`},
		{URL: kitRepoURL("repo-ruleset", "/environments/production/deployment_protection_rules?per_page=100"), Body: `{"total_count":1,"custom_deployment_protection_rules":[{"id":1,"enabled":true,"app":{"id":100,"slug":"deploy-gate"}}]}`},
		{URL: kitRepoURL("repo-ruleset", "/environments/staging/deployment_protection_rules?per_page=100"), Body: `{"total_count":0,"custom_deployment_protection_rules":[]}`},

		{URL: kitOrgURL("/audit-log?phrase=created%3A%3E%3D2026-10-10&per_page=100"), Body: kitJSON([]any{
			map[string]any{"action": "repo.create", "actor": "alice", "repo": "test-org/repo-ruleset", "created_at": 1760000000000},
			map[string]any{"action": "member_add", "actor": "bob", "created_at": 1760000100000},
			map[string]any{"action": "issues.opened", "actor": "bob", "created_at": 1760000200000},
		})},
		{URL: kitOrgURL("/installations?per_page=100"), Header: kitNextPage("/organizations/1/installations"), Body: kitJSON(map[string]any{"total_count": 2, "installations": []any{map[string]any{
			"app_slug": "dependabot", "app_id": 99, "permissions": map[string]any{"metadata": "read"},
			"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z", "repository_selection": "all", "events": []any{"push"},
		}}})},
		{URL: kitAPI + "/organizations/1/installations?per_page=100&page=2", Body: kitJSON(map[string]any{"total_count": 2, "installations": []any{map[string]any{
			"app_slug": "renovate", "app_id": 100, "permissions": map[string]any{"contents": "write", "pull_requests": "write"},
			"suspended_at": "2026-06-01T00:00:00Z", "created_at": "2026-03-01T00:00:00Z", "updated_at": "2026-06-01T00:00:00Z", "repository_selection": "selected", "events": []any{"pull_request"},
		}}})},
		{URL: kitOrgURL("/personal-access-tokens?per_page=100"), Body: kitJSON([]any{map[string]any{
			"id": 5, "owner": map[string]any{"login": "alice"}, "token_name": "ci-token",
			"permissions":      map[string]any{"organization": map[string]any{"members": "read"}, "repository": map[string]any{"contents": "read"}},
			"token_expires_at": "2026-12-01T00:00:00Z",
		}})},

		{URL: kitOrgURL("/members?per_page=100"), Body: `[{"login":"alice"},{"login":"bob"}]`},
		{URL: kitOrgURL("/members?role=admin&per_page=100"), Body: `[{"login":"alice"}]`},
		{URL: kitOrgURL("/outside_collaborators?per_page=100"), Body: `[{"login":"carol"}]`},
		{URL: kitOrgURL("/members?filter=2fa_disabled&per_page=100"), Body: `[{"login":"bob"}]`},
		{URL: kitOrgURL("/invitations?per_page=100"), Body: `[{"id":1,"login":"dana"}]`},
		{URL: kitAPI + "/users/carol", Body: `{"login":"carol","name":"Carol Chen"}`},
		{Operation: "github.member_names.list", Method: http.MethodPost, URL: kitGraphQL, Body: kitJSON(map[string]any{"data": map[string]any{"organization": map[string]any{
			"membersWithRole": map[string]any{
				"nodes":    []any{map[string]any{"login": "alice", "name": "Alice Adams"}, map[string]any{"login": "bob", "name": nil}},
				"pageInfo": map[string]any{"hasNextPage": false, "endCursor": nil},
			},
		}}})},
	}
	return responses
}

// codeownersMaxBytesForKit sits at the hashing limit, so the sensitivity
// check's added byte crosses it and drops the hash.
const codeownersMaxBytesForKit = 1 << 20

// kitResponses answer every call a clean internal-level run makes. An
// internal run makes the same calls as an audit run.
func kitResponses() []collectortest.Response {
	return append(kitTrustResponses(), kitAuditResponses()...)
}

// replaceResponse swaps the response for the same method and URL.
func replaceResponse(responses []collectortest.Response, replacement collectortest.Response) []collectortest.Response {
	out := append([]collectortest.Response(nil), responses...)
	for i, r := range out {
		if r.URL == replacement.URL && r.Method == replacement.Method && r.Operation == replacement.Operation {
			out[i] = replacement
			return out
		}
	}
	panic("no response to replace for " + replacement.URL)
}

// kitEmptyTenantResponses answer a run against an organization with no
// repositories, members, or other resources.
func kitEmptyTenantResponses() []collectortest.Response {
	return []collectortest.Response{
		kitTokenResponse(),
		kitOrgResponse(false),
		{Operation: "github.repositories.list", Method: http.MethodPost, URL: kitGraphQL, Body: kitRepoPage([]any{}, "")},
		{URL: kitOrgURL("/hooks?per_page=100"), Body: `[]`},
		{URL: kitOrgURL("/actions/runners?per_page=100"), Body: `{"total_count":0,"runners":[]}`},
		{URL: kitOrgURL("/actions/secrets?per_page=100"), Body: `{"total_count":0,"secrets":[]}`},
		{URL: kitOrgURL("/audit-log?phrase=created%3A%3E%3D2026-10-10&per_page=100"), Body: `[]`},
		{URL: kitOrgURL("/installations?per_page=100"), Body: `{"total_count":0,"installations":[]}`},
		{URL: kitOrgURL("/personal-access-tokens?per_page=100"), Body: `[]`},
		{URL: kitOrgURL("/members?per_page=100"), Body: `[]`},
		{URL: kitOrgURL("/members?role=admin&per_page=100"), Body: `[]`},
		{URL: kitOrgURL("/outside_collaborators?per_page=100"), Body: `[]`},
		{URL: kitOrgURL("/members?filter=2fa_disabled&per_page=100"), Body: `[]`},
		{URL: kitOrgURL("/invitations?per_page=100"), Body: `[]`},
		{Operation: "github.member_names.list", Method: http.MethodPost, URL: kitGraphQL, Body: kitJSON(map[string]any{"data": map[string]any{"organization": map[string]any{
			"membersWithRole": map[string]any{"nodes": []any{}, "pageInfo": map[string]any{"hasNextPage": false, "endCursor": nil}},
		}}})},
	}
}

// kitReadOnlyResponses answer the clean run as GitHub does for a token
// without admin or owner rights: no two-factor setting, no
// security_and_analysis block, and no ruleset bypass lists.
func kitReadOnlyResponses() []collectortest.Response {
	responses := replaceResponse(kitResponses(), collectortest.Response{URL: kitOrgURL(""), Body: kitJSON(map[string]any{"login": kitOrg})})
	for _, repo := range kitIncluded {
		responses = replaceResponse(responses, collectortest.Response{URL: kitRepoURL(repo, ""), Body: kitJSON(map[string]any{"name": repo})})
	}
	responses = replaceResponse(responses, collectortest.Response{URL: kitRepoURL("repo-ruleset", "/rulesets/1001?includes_parents=true"), Body: kitTestdata("ruleset_1001.json")})
	responses = replaceResponse(responses, collectortest.Response{URL: kitRepoURL("classic-and-org", "/rulesets/2001?includes_parents=true"), Body: kitTestdata("ruleset_2001.json")})
	return replaceResponse(responses, collectortest.Response{URL: kitRepoURL("org-ruleset", "/rulesets/2001?includes_parents=true"), Body: kitTestdata("ruleset_2001.json")})
}
