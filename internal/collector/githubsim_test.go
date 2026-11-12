package collector

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// githubSim answers the calls the collector makes at the audit level for an
// organization a roster describes, as GitHub's REST and GraphQL APIs answer
// a GitHub App installed on it. Each item is a copy of one the sandboxes'
// recordings hold, the closest kind they have, with the fields the roster
// decides set, so the answers keep GitHub's nulls, optional fields and
// envelopes. The paging, the refusals, and the permission each call needs
// follow GitHub's API reference, not the collector.
//
// The vcs block is the organization, which must be the kit's. An account of
// kind member is a member, listed among the owners when it holds the admin
// role, and one of kind outside_collaborator an outside collaborator. An
// account that is not enabled is an invitation not yet accepted. An account
// has two-factor authentication when one of its methods maps to MFA, and a
// linked SAML identity when one of its logins maps to SSO and the
// organization has single sign-on, with a SCIM record when its provisioning
// both creates and deactivates accounts. The apps are the GitHub App
// installations, the collector app among them, and enabled false marks a
// suspended one. The collector app is installed on selected repositories
// when it can't read one.
//
// A repository's protection keyed classic is its classic branch protection,
// and every other one a ruleset, whose enforcement is GitHub's. A ruleset
// belongs to the repository unless its source extra is organization, and
// GitHub lists only an active ruleset's rules on the branch. The scanning
// block gives each repository's Dependabot alerts, code scanning and secret
// scanning, and its open findings are the open alerts. A credential with
// repositories is a deploy key on its one repository, and one without a
// fine-grained personal access token approved for the organization, which a
// member owns. Its permissions are read or write. An inactive deploy key is
// one GitHub disabled, and an inactive token one that expired.
//
// The vendor extras give an account's login, a repository's visibility,
// whether it is archived and its default branch, a code scanning setup that
// is advanced rather than default (code_scanning_setup), a classic
// protection's enforce_admins, a ruleset's name and source, an app's slug,
// and the collector app's permissions. A rule's extras are its GitHub
// parameters, with a classic rule's named as its ruleset counterpart's.
type githubSim struct {
	r        *roster.Roster
	rec      *simulate.Recorded
	now      time.Time
	pageSize int
	granted  []string
	t        *simulate.Tenant
}

// simRecordingNames are the sandboxes whose recordings the simulator copies
// items from, which TestRecord writes.
var simRecordingNames = []string{"github-compliant", "github-noncompliant"}

func simRecordingPath(name string) string {
	return filepath.Join("testdata", "recordings", name+".json")
}

// simRecorded is the sandboxes' recordings as one, since each holds answers
// the other lacks: github-compliant's protections require status checks and
// signed commits, and only github-noncompliant was recorded at the audit
// level.
var simRecorded = sync.OnceValues(func() (*simulate.Recorded, error) {
	var responses []json.RawMessage
	for _, name := range simRecordingNames {
		raw, err := os.ReadFile(simRecordingPath(name))
		if err != nil {
			return nil, err
		}
		var rec struct {
			Responses []json.RawMessage `json:"responses"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, err
		}
		responses = append(responses, rec.Responses...)
	}
	f, err := os.CreateTemp("", "github-sim-recordings-*.json")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := json.NewEncoder(f).Encode(map[string]any{"name": "recordings", "responses": responses}); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return simulate.LoadRecorded(f.Name())
})

func simRecording(t testing.TB) *simulate.Recorded {
	t.Helper()
	rec, err := simRecorded()
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// simPermissions are the GitHub App permissions the collector app holds
// unless its permissions extra says otherwise: those github-noncompliant's
// App has (checklist step 8), which leave out Personal access tokens.
var simPermissions = []string{
	"actions", "administration", "contents", "members", "metadata", "organization_administration", "organization_hooks",
	"organization_secrets", "organization_self_hosted_runners", "repository_hooks", "secret_scanning_alerts", "security_events",
	"vulnerability_alerts",
}

// simPageSize is the page size the collector asks for and GitHub honors.
const simPageSize = 100

func newGitHubSim(r *roster.Roster, rec *simulate.Recorded, now time.Time, pageSize int) *githubSim {
	if r.VCS == nil || r.VCS.Organization != kitOrg {
		panic("githubSim: the roster's vcs block must be the organization " + kitOrg)
	}
	s := &githubSim{r: r, rec: rec, now: now, pageSize: pageSize, granted: slices.Clone(simPermissions)}
	i := slices.IndexFunc(r.Apps, func(a roster.App) bool { return a.Key == "collector" })
	if i < 0 {
		panic("githubSim: the roster has no collector app")
	}
	simulate.Extra(r.Apps[i].Extra, "permissions", &s.granted)
	return s
}

// reads is a call that needs a GitHub App permission at read access, as
// GitHub's API reference lists it.
func reads(permission string) simulate.Need { return simulate.Needs([]string{permission}) }

// simDenied is GitHub's answer to a GitHub App without the call's
// permission.
func simDenied(simulate.Refusal) collectortest.Response {
	return simError(http.StatusForbidden, "Resource not accessible by integration")
}

func simError(status int, message string) collectortest.Response {
	return collectortest.Response{Status: status, Body: simulate.JSON(map[string]any{
		"message": message, "documentation_url": "https://docs.github.com/rest", "status": strconv.Itoa(status),
	})}
}

func (s *githubSim) holds(permission string) bool { return slices.Contains(s.granted, permission) }

// fail answers a call with GitHub's error, unless the App lacks the call's
// permission, which GitHub checks first.
func (s *githubSim) fail(op, u string, n simulate.Need, status int, message string) {
	if _, refused := s.t.Refused(n); refused {
		s.t.Get(op, u, n, nil)
		return
	}
	r := simError(status, message)
	r.Operation, r.URL = op, u
	s.t.Add(r)
}

func (s *githubSim) responses() []collectortest.Response {
	s.t = &simulate.Tenant{Granted: s.granted, PageSize: s.pageSize, Refuse: simDenied}
	s.token()
	s.organization()
	s.repositories()
	for _, repo := range s.r.VCS.Repositories {
		if !repo.Unreadable {
			s.repository(repo)
		}
	}
	s.people()
	s.installations()
	s.tokens()
	s.surfaces()
	return s.t.Responses()
}

func (s *githubSim) orgURL(rest string) string { return kitOrgURL(rest) }

// login is an account's GitHub login.
func (s *githubSim) login(a roster.Account) string {
	login := strings.ReplaceAll(a.Key, "_", "-")
	simulate.Extra(a.Extra, "login", &login)
	return login
}

// at is the time days before the run, as GitHub writes it.
func (s *githubSim) at(days int) string {
	return s.now.Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339)
}

// simInt is a stable numeric ID for a roster key, as GitHub's IDs are.
func simInt(kind, key string) int64 {
	sum := sha256.Sum256([]byte(kind + "/" + key))
	return 100000000 + int64(binary.BigEndian.Uint32(sum[:4])%900000000)
}

// selected reports whether the collector app is installed on selected
// repositories, as it is when it can't read one.
func (s *githubSim) selected() bool {
	return slices.ContainsFunc(s.r.VCS.Repositories, func(repo roster.Repository) bool { return repo.Unreadable })
}

func (s *githubSim) selection() string {
	if s.selected() {
		return "selected"
	}
	return "all"
}

func (s *githubSim) token() {
	permissions := map[string]any{}
	for _, p := range s.granted {
		permissions[p] = "read"
	}
	body := s.rec.Body("github.installation_token.create")
	body["token"], body["expires_at"], body["permissions"], body["repository_selection"] = kitToken, "2099-01-01T00:00:00Z", permissions, s.selection()
	s.t.Add(collectortest.Response{
		Operation: "github.installation_token.create", Method: http.MethodPost, Status: http.StatusCreated,
		URL: fmt.Sprintf("%s/app/installations/%d/access_tokens", kitAPI, kitInstallationID), Body: simulate.JSON(body),
	})
}

// simOwnerOnly are the fields of an organization GitHub shows only to its
// owners, and to a GitHub App with Organization administration.
var simOwnerOnly = []string{
	"total_private_repos", "owned_private_repos", "private_gists", "disk_usage", "collaborators", "billing_email",
	"default_repository_permission", "members_can_create_repositories", "two_factor_requirement_enabled",
	"members_allowed_repository_creation_type", "members_can_create_public_repositories",
	"members_can_create_private_repositories", "members_can_create_internal_repositories", "members_can_create_pages",
	"members_can_fork_private_repositories", "web_commit_signoff_required", "deploy_keys_enabled_for_repositories",
	"members_can_delete_repositories", "members_can_change_repo_visibility", "members_can_invite_outside_collaborators",
	"members_can_delete_issues", "display_commenter_full_name_setting_enabled", "readers_can_create_discussions",
	"members_can_create_teams", "members_can_view_dependency_insights", "default_repository_branch",
	"members_can_create_public_pages", "members_can_create_private_pages", "plan",
	"advanced_security_enabled_for_new_repositories", "dependabot_alerts_enabled_for_new_repositories",
	"dependabot_security_updates_enabled_for_new_repositories", "dependency_graph_enabled_for_new_repositories",
	"secret_scanning_enabled_for_new_repositories", "secret_scanning_push_protection_enabled_for_new_repositories",
	"secret_scanning_push_protection_custom_link_enabled", "secret_scanning_push_protection_custom_link",
	"secret_scanning_validity_checks_enabled",
}

// organization answers GET /orgs/{org}, which the collector reads to sign
// in and again for the organization's settings. The members' base
// permission is read when the roster sets none, as GitHub sets it for a new
// organization.
func (s *githubSim) organization() {
	g := s.r.VCS
	public, private := 0, 0
	for _, repo := range g.Repositories {
		if s.visibility(repo) == "public" {
			public++
		} else {
			private++
		}
	}
	body := s.rec.Body("github.orgs.get")
	body["login"], body["public_repos"] = g.Organization, public
	body["owned_private_repos"], body["total_private_repos"] = private, private
	body["two_factor_requirement_enabled"] = g.TwoFactorRequirement
	body["default_repository_permission"] = cmp.Or(g.BasePermission, "read")
	if !s.holds("organization_administration") {
		for _, field := range simOwnerOnly {
			delete(body, field)
		}
	}
	for _, op := range []string{"github.orgs.get", "github.org_settings.get"} {
		s.t.Get(op, s.orgURL(""), simulate.Need{}, body)
	}
}

func (s *githubSim) visibility(repo roster.Repository) string {
	visibility := "public"
	simulate.Extra(repo.Extra, "visibility", &visibility)
	return visibility
}

func (s *githubSim) archived(repo roster.Repository) bool {
	archived := false
	simulate.Extra(repo.Extra, "archived", &archived)
	return archived
}

func (s *githubSim) branch(repo roster.Repository) string {
	branch := "main"
	simulate.Extra(repo.Extra, "default_branch", &branch)
	return branch
}

// scanned reports whether the vendor scanner, such as Dependabot alerts,
// scans the repository.
func (s *githubSim) scanned(repo, scanner string) bool {
	if s.r.Scanning == nil {
		return false
	}
	for _, res := range s.r.Scanning.Resources {
		if status, ok := res.Scans[scanner]; ok && res.Key == repo {
			return s.r.Terms.VulnScanStatuses[status] == roster.VulnScanned
		}
	}
	return false
}

// findings are the repository's open findings of the vendor scanner.
func (s *githubSim) findings(repo, scanner string) []roster.VulnFinding {
	if s.r.Scanning == nil {
		return nil
	}
	var out []roster.VulnFinding
	for _, res := range s.r.Scanning.Resources {
		for _, f := range res.Findings {
			if res.Key == repo && f.Scanner == scanner && s.r.Terms.VulnFindingStates[f.State] == roster.VulnOpen {
				out = append(out, f)
			}
		}
	}
	return out
}

// classicRule renders a repository's classic branch protection as GraphQL's
// BranchProtectionRule, or nil for none.
func (s *githubSim) classicRule(repo roster.Repository) any {
	i := slices.IndexFunc(repo.Protections, func(p roster.BranchProtection) bool { return p.Key == "classic" })
	if i < 0 {
		return nil
	}
	p := repo.Protections[i]
	rules := map[string]roster.BranchRule{}
	for _, rule := range p.Rules {
		rules[rule.Type] = rule
	}
	param := func(rule, name string) bool {
		on := false
		simulate.Extra(rules[rule].Extra, name, &on)
		return on
	}
	enforceAdmins := false
	simulate.Extra(p.Extra, "enforce_admins", &enforceAdmins)
	reviews, requiresReviews := rules["required_pull_request_reviews"]
	var count any
	if requiresReviews {
		count = reviews.Approvals
	}
	has := func(rule string) bool { _, ok := rules[rule]; return ok }
	return map[string]any{
		"requiresApprovingReviews":       requiresReviews,
		"requiredApprovingReviewCount":   count,
		"dismissesStaleReviews":          param("required_pull_request_reviews", "dismiss_stale_reviews_on_push"),
		"requiresCodeOwnerReviews":       param("required_pull_request_reviews", "require_code_owner_review"),
		"requiresStatusChecks":           has("required_status_checks"),
		"requiresCommitSignatures":       has("required_signatures"),
		"isAdminEnforced":                enforceAdmins,
		"requiresLinearHistory":          has("required_linear_history"),
		"allowsForcePushes":              !has("block_force_pushes"),
		"allowsDeletions":                !has("block_deletions"),
		"requiresConversationResolution": false,
	}
}

// recordedNodes are the nodes the recorded GraphQL answers to op hold at
// path, field names joined by / below data.
func (s *githubSim) recordedNodes(op, path string) []map[string]any {
	var out []map[string]any
	for _, data := range s.rec.Items(op, "data") {
		var node any = data
		for _, part := range strings.Split(path, "/") {
			m, _ := node.(map[string]any)
			node = m[part]
		}
		list, _ := node.([]any)
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// likeNode returns a copy of the first recorded node pick accepts, or of
// the first node.
func (s *githubSim) likeNode(op, path string, pick func(map[string]any) bool) map[string]any {
	nodes := s.recordedNodes(op, path)
	if len(nodes) == 0 {
		panic("githubSim: the recordings hold no node for " + op)
	}
	i := max(slices.IndexFunc(nodes, pick), 0)
	var out map[string]any
	if err := json.Unmarshal([]byte(simulate.JSON(nodes[i])), &out); err != nil {
		panic(err)
	}
	return out
}

// repositories answers the GraphQL list of the organization's repositories,
// and the installation's repositories when it has a selection. GitHub lists
// every public repository to any caller, and hides a classic protection
// from a GitHub App without Administration, with no error.
func (s *githubSim) repositories() {
	var nodes []any
	for _, repo := range s.r.VCS.Repositories {
		if !repo.Unreadable || s.visibility(repo) == "public" {
			nodes = append(nodes, s.repoNode(repo))
		}
	}
	s.graphQL("github.repositories.list", reads("metadata"), "organization/repositories", nodes)

	if !s.selected() {
		return
	}
	var installed []any
	for _, repo := range s.r.VCS.Repositories {
		if repo.Unreadable {
			continue
		}
		item := s.rec.Like("github.installation_repositories.list", "repositories")
		item["id"], item["node_id"], item["name"], item["full_name"] = simInt("repository", repo.Key), "node-"+repo.Key, repo.Key, kitOrg+"/"+repo.Key
		item["private"], item["visibility"], item["archived"] = s.visibility(repo) != "public", s.visibility(repo), s.archived(repo)
		item["html_url"], item["url"] = "https://github.com/"+kitOrg+"/"+repo.Key, kitRepoURL(repo.Key, "")
		installed = append(installed, item)
	}
	envelope := s.rec.Body("github.installation_repositories.list")
	delete(envelope, "repositories")
	envelope["total_count"], envelope["repository_selection"] = len(installed), "selected"
	s.t.List("github.installation_repositories.list", kitInstallationReposURL, simulate.Need{},
		simLinks{Items: "repositories", Envelope: envelope, Size: simPageSize}, installed)
}

// repoNode renders a repository as the GraphQL list holds it.
func (s *githubSim) repoNode(repo roster.Repository) any {
	classic := s.classicRule(repo)
	if !s.holds("administration") {
		classic = nil
	}
	node := s.likeNode("github.repositories.list", "organization/repositories/nodes", func(m map[string]any) bool {
		ref, _ := m["defaultBranchRef"].(map[string]any)
		return (ref["branchProtectionRule"] != nil) == (classic != nil)
	})
	node["name"], node["isArchived"], node["visibility"] = repo.Key, s.archived(repo), strings.ToUpper(s.visibility(repo))
	node["description"] = "Simulated repository " + repo.Key
	node["defaultBranchRef"] = map[string]any{"name": s.branch(repo), "branchProtectionRule": classic}
	node["hasVulnerabilityAlertsEnabled"] = s.scanned(repo.Key, "Dependabot alerts")
	return node
}

// graphQL answers a GraphQL connection at path below data with nodes, or
// GitHub's FORBIDDEN error when the App lacks the call's permission.
func (s *githubSim) graphQL(op string, n simulate.Need, path string, nodes []any) {
	if _, refused := s.t.Refused(n); refused {
		parent, field, _ := strings.Cut(path, "/")
		s.t.Add(collectortest.Response{Operation: op, Method: http.MethodPost, URL: kitGraphQL, Body: simulate.JSON(map[string]any{
			"data":   map[string]any{parent: map[string]any{field: nil}},
			"errors": []any{map[string]any{"type": "FORBIDDEN", "path": []any{parent, field}, "message": "Resource not accessible by integration"}},
		})})
		return
	}
	s.t.List(op, kitGraphQL, n, simGraphQLPages{Path: "data/" + path, Size: simPageSize}, nodes)
}

// repository answers the calls the collector makes about one repository it
// can read.
func (s *githubSim) repository(repo roster.Repository) {
	s.branchRules(repo)
	s.securitySettings(repo)
	s.codeScanning(repo)
	s.alerts(repo)
	for _, path := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
		s.fail("github.repo_contents.get", kitRepoURL(repo.Key, "/contents/"+path+"?"), reads("contents"), http.StatusNotFound, "Not Found")
	}
	s.t.List("github.repo_hooks.list", kitRepoURL(repo.Key, "/hooks?per_page=100"), reads("repository_hooks"), simLinks{Size: simPageSize}, nil)
	s.deployKeys(repo)
	s.t.List("github.repo_runners.list", kitRepoURL(repo.Key, "/actions/runners?per_page=100"), reads("administration"),
		simLinks{Items: "runners", Envelope: map[string]any{"total_count": 0}, Size: simPageSize}, nil)
	s.t.List("github.environments.list", kitRepoURL(repo.Key, "/environments?per_page=100&page=1"), reads("actions"),
		simLinks{Items: "environments", Envelope: map[string]any{"total_count": 0}, Size: simPageSize}, nil)
}

// ruleset gives a ruleset protection's ID, name, and source.
func (s *githubSim) ruleset(repo roster.Repository, p roster.BranchProtection) (id int64, name, sourceType, source string) {
	name, from := strings.TrimPrefix(p.Key, "ruleset:"), "repository"
	simulate.Extra(p.Extra, "name", &name)
	simulate.Extra(p.Extra, "source", &from)
	if from == "organization" {
		return simInt("ruleset", p.Key), name, "Organization", kitOrg
	}
	return simInt("ruleset", repo.Key+"/"+p.Key), name, "Repository", kitOrg + "/" + repo.Key
}

// ruleItem renders a ruleset rule as GitHub lists it, from a recorded rule
// of its type, with its approvals, checks, and extras in its parameters.
func (s *githubSim) ruleItem(op string, rule roster.BranchRule) map[string]any {
	item := s.rec.Like(op, "", func(m map[string]any) bool { return m["type"] == rule.Type }, func(m map[string]any) bool { return m["parameters"] == nil })
	if op == "github.rulesets.get" {
		item = s.recordedRule(rule.Type)
	}
	item["type"] = rule.Type
	params, _ := item["parameters"].(map[string]any)
	if params == nil && len(rule.Extra) > 0 {
		params = map[string]any{}
	}
	switch rule.Type {
	case "pull_request":
		params["required_approving_review_count"] = rule.Approvals
	case "required_status_checks":
		var checks []any
		for _, c := range rule.Checks {
			checks = append(checks, map[string]any{"context": c})
		}
		params["required_status_checks"] = nonNil(checks)
	}
	for name, raw := range rule.Extra {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			panic(err)
		}
		params[name] = v
	}
	if params == nil {
		delete(item, "parameters")
	} else {
		item["parameters"] = params
	}
	return item
}

// recordedRule is a copy of a rule of type typ from the recorded rulesets,
// or a bare rule of that type.
func (s *githubSim) recordedRule(typ string) map[string]any {
	for _, rs := range s.rec.Items("github.rulesets.get", "") {
		rules, _ := rs["rules"].([]any)
		for _, r := range rules {
			if m, ok := r.(map[string]any); ok && m["type"] == typ {
				return m
			}
		}
	}
	return map[string]any{"type": typ}
}

// branchRules answers the rules on the repository's default branch, which
// GitHub gives for active rulesets only, and each ruleset's details.
func (s *githubSim) branchRules(repo roster.Repository) {
	var listed []any
	for _, p := range repo.Protections {
		if p.Key == "classic" {
			continue
		}
		id, name, sourceType, source := s.ruleset(repo, p)
		var rules []any
		for _, rule := range p.Rules {
			rules = append(rules, s.ruleItem("github.rulesets.get", rule))
			if p.Enforcement != "active" {
				continue
			}
			item := s.ruleItem("github.branch_rules.list", rule)
			item["ruleset_source_type"], item["ruleset_source"], item["ruleset_id"] = sourceType, source, id
			listed = append(listed, item)
		}
		detail := s.rec.Body("github.rulesets.get")
		detail["id"], detail["name"], detail["enforcement"], detail["source_type"], detail["source"], detail["rules"] = id, name, p.Enforcement, sourceType, source, nonNil(rules)
		detail["node_id"] = "node-ruleset-" + strconv.FormatInt(id, 10)
		self := kitRepoURL(repo.Key, "/rulesets/"+strconv.FormatInt(id, 10))
		simulate.Set(detail, "_links/self/href", self)
		simulate.Set(detail, "_links/html/href", "https://github.com/"+source+"/rules/"+strconv.FormatInt(id, 10))
		s.t.Get("github.rulesets.get", self+"?includes_parents=true", reads("metadata"), detail)
	}
	s.t.List("github.branch_rules.list", kitRepoURL(repo.Key, "/rules/branches/"+s.branch(repo)+"?per_page=100"), reads("metadata"), simLinks{Size: simPageSize}, listed)
}

// securitySettings answers GET /repos/{owner}/{repo}, whose
// security_and_analysis block GitHub shows only to a caller with admin
// access, Administration for a GitHub App. The push protection and
// Dependabot security updates extras are enabled or disabled.
func (s *githubSim) securitySettings(repo roster.Repository) {
	item := s.rec.Like("github.repos.get", "", func(m map[string]any) bool { return m["security_and_analysis"] != nil })
	item["id"], item["node_id"], item["name"], item["full_name"] = simInt("repository", repo.Key), "node-"+repo.Key, repo.Key, kitOrg+"/"+repo.Key
	item["private"], item["visibility"], item["archived"], item["default_branch"] = s.visibility(repo) != "public", s.visibility(repo), s.archived(repo), s.branch(repo)
	item["html_url"], item["url"], item["description"] = "https://github.com/"+kitOrg+"/"+repo.Key, kitRepoURL(repo.Key, ""), "Simulated repository "+repo.Key
	status := func(on bool) string {
		if on {
			return "enabled"
		}
		return "disabled"
	}
	pushProtection, updates := "disabled", "disabled"
	simulate.Extra(repo.Extra, "secret_scanning_push_protection", &pushProtection)
	simulate.Extra(repo.Extra, "dependabot_security_updates", &updates)
	simulate.Set(item, "security_and_analysis/secret_scanning/status", status(s.scanned(repo.Key, "Secret scanning")))
	simulate.Set(item, "security_and_analysis/secret_scanning_push_protection/status", pushProtection)
	simulate.Set(item, "security_and_analysis/dependabot_security_updates/status", updates)
	if !s.holds("administration") {
		delete(item, "security_and_analysis")
	}
	s.t.Get("github.repos.get", kitRepoURL(repo.Key, ""), reads("metadata"), item)
}

// codeScanning answers the code scanning default setup, and the analyses
// the collector reads when default setup is off. Code scanning set up with
// a workflow (code_scanning_setup advanced) shows only in the analyses.
func (s *githubSim) codeScanning(repo roster.Repository) {
	on := s.scanned(repo.Key, "Code scanning")
	setup := "default"
	simulate.Extra(repo.Extra, "code_scanning_setup", &setup)
	state := "not-configured"
	if on && setup == "default" {
		state = "configured"
	}
	body := s.rec.Like("github.code_scanning_default_setup.get", "", func(m map[string]any) bool { return m["state"] == state })
	s.t.Get("github.code_scanning_default_setup.get", kitRepoURL(repo.Key, "/code-scanning/default-setup"), reads("administration"), body)
	analyses := kitRepoURL(repo.Key, "/code-scanning/analyses?per_page=1")
	if on && setup == "advanced" {
		s.t.Get("github.code_scanning_analyses.list", analyses, reads("security_events"), []any{s.rec.Like("github.code_scanning_analyses.list", "")})
		return
	}
	s.fail("github.code_scanning_analyses.list", analyses, reads("security_events"), http.StatusNotFound, "no analysis found")
}

// alerts answers the open alerts of each kind. GitHub answers 404 for code
// scanning and secret scanning alerts when the feature is off, and 403 for
// Dependabot alerts, so a repository has alerts only from a scanner that
// scans it.
func (s *githubSim) alerts(repo roster.Repository) {
	for _, scanner := range []string{"Secret scanning", "Code scanning", "Dependabot alerts"} {
		if len(s.findings(repo.Key, scanner)) > 0 && !s.scanned(repo.Key, scanner) {
			panic("githubSim: " + repo.Key + " has open " + scanner + " findings, and the scanner is off")
		}
	}
	if s.scanned(repo.Key, "Secret scanning") {
		var alerts []any
		for i, f := range s.findings(repo.Key, "Secret scanning") {
			alerts = append(alerts, map[string]any{
				"number": i + 1, "state": "open", "created_at": s.at(*f.OpenDays), "updated_at": s.at(*f.OpenDays),
				"secret_type": "github_personal_access_token", "secret_type_display_name": "GitHub Personal Access Token",
				"resolution": nil, "resolved_at": nil, "resolved_by": nil,
			})
		}
		s.t.List("github.secret_scanning_alerts.list", kitAlertListURL(repo.Key, "secret-scanning"), reads("secret_scanning_alerts"), simLinks{Size: simPageSize}, alerts)
		s.t.List("github.secret_scanning_alerts.list", kitGenericSecretsURL(repo.Key), reads("secret_scanning_alerts"), simLinks{Size: simPageSize}, nil)
	} else {
		for _, u := range []string{kitAlertListURL(repo.Key, "secret-scanning"), kitGenericSecretsURL(repo.Key)} {
			s.fail("github.secret_scanning_alerts.list", u, reads("secret_scanning_alerts"), http.StatusNotFound, "Secret scanning is disabled on this repository.")
		}
	}

	codeURL := kitAlertListURL(repo.Key, "code-scanning")
	if s.scanned(repo.Key, "Code scanning") {
		var alerts []any
		for i, f := range s.findings(repo.Key, "Code scanning") {
			alerts = append(alerts, map[string]any{
				"number": i + 1, "state": "open", "created_at": s.at(*f.OpenDays), "updated_at": s.at(*f.OpenDays),
				"rule":                 map[string]any{"id": "js/sql-injection", "severity": "error", "security_severity_level": nonEmpty(f.Severity)},
				"tool":                 map[string]any{"name": "CodeQL", "guid": nil, "version": "2.27.2"},
				"most_recent_instance": map[string]any{"ref": "refs/heads/" + s.branch(repo), "state": "open", "location": map[string]any{"path": "src/db.js"}},
				"dismissed_by":         nil, "dismissed_at": nil, "dismissed_reason": nil,
			})
		}
		s.t.List("github.code_scanning_alerts.list", codeURL, reads("security_events"), simLinks{Size: simPageSize}, alerts)
	} else {
		s.fail("github.code_scanning_alerts.list", codeURL, reads("security_events"), http.StatusNotFound, "no analysis found")
	}

	depURL := kitAlertListURL(repo.Key, "dependabot")
	if s.scanned(repo.Key, "Dependabot alerts") {
		var alerts []any
		for i, f := range s.findings(repo.Key, "Dependabot alerts") {
			alerts = append(alerts, map[string]any{
				"number": i + 1, "state": "open", "created_at": s.at(*f.OpenDays), "updated_at": s.at(*f.OpenDays),
				"security_advisory":      map[string]any{"ghsa_id": "GHSA-sim0-0000-000" + strconv.Itoa(i), "cve_id": nil, "severity": f.Severity},
				"security_vulnerability": map[string]any{"severity": f.Severity, "package": map[string]any{"ecosystem": "npm", "name": "left-pad"}},
				"dependency":             map[string]any{"package": map[string]any{"ecosystem": "npm", "name": "left-pad"}, "manifest_path": "package-lock.json", "scope": "runtime"},
			})
		}
		s.t.List("github.dependabot_alerts.list", depURL, reads("vulnerability_alerts"), simLinks{Size: simPageSize}, alerts)
	} else {
		s.fail("github.dependabot_alerts.list", depURL, reads("vulnerability_alerts"), http.StatusForbidden, "Dependabot alerts are disabled for this repository.")
	}
}

// nonEmpty is s, or null for an empty string.
func nonEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// permission is a credential's GitHub access, read or write.
func (s *githubSim) permission(m roster.MachineCredential) string {
	switch p := s.r.Terms.VCSCredentialPermissions[m.Permissions]; p {
	case roster.PermissionsRead, roster.PermissionsWrite:
		return p
	default:
		panic(fmt.Sprintf("githubSim: credential %s has %s permissions, and a deploy key or fine-grained token reads or writes", m.Key, p))
	}
}

// deployKeys answers a repository's deploy keys. GitHub reports when each
// was added and never lets one expire.
func (s *githubSim) deployKeys(repo roster.Repository) {
	var keys []any
	for _, m := range s.r.VCS.Credentials {
		if !slices.Contains(m.Repositories, repo.Key) {
			continue
		}
		if len(m.Repositories) != 1 || m.CreatedDaysAgo == nil || m.ExpiresInDays != nil {
			panic("githubSim: deploy key " + m.Key + " must be on one repository, with a creation day and no expiry")
		}
		var lastUsed any
		if m.LastUsedDaysAgo != nil {
			lastUsed = s.at(*m.LastUsedDaysAgo)
		}
		id := simInt("deploy key", m.Key)
		keys = append(keys, map[string]any{
			"id": id, "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISim" + m.Key, "url": kitRepoURL(repo.Key, "/keys/"+strconv.FormatInt(id, 10)),
			"title": m.Key, "verified": true, "created_at": s.at(*m.CreatedDaysAgo), "read_only": s.permission(m) == roster.PermissionsRead,
			"added_by": "member-1", "last_used": lastUsed, "enabled": m.Active,
		})
	}
	s.t.List("github.deploy_keys.list", kitRepoURL(repo.Key, "/keys?per_page=100"), reads("administration"), simLinks{Size: simPageSize}, keys)
}

// people answers the organization's members, owners, outside
// collaborators, those without two-factor authentication, invitations,
// names, and SAML identities.
func (s *githubSim) people() {
	var members, owners, collaborators, membersOff, collaboratorsOff, invited, names, identities []any
	user := func(a roster.Account) any {
		item := s.rec.Like("github.org_members.list", "")
		login := s.login(a)
		item["login"], item["id"], item["node_id"] = login, simInt("user", a.Key), "node-user-"+a.Key
		item["url"], item["html_url"] = kitAPI+"/users/"+login, "https://github.com/"+login
		return item
	}
	hasMFA := func(a roster.Account) bool { return s.r.MFAClass(a) != roster.MFANone }
	sso := func(a roster.Account) bool {
		return slices.ContainsFunc(a.Logins, func(l string) bool { return s.r.Terms.LoginMethods[l] == roster.LoginSSO })
	}
	scim := false
	for _, f := range s.r.VCS.Provisioning {
		scim = scim || s.r.Terms.ProvisioningFeatures[f] == roster.ProvisionCreate
	}
	scim = scim && slices.ContainsFunc(s.r.VCS.Provisioning, func(f string) bool { return s.r.Terms.ProvisioningFeatures[f] == roster.ProvisionDeactivate })
	for _, a := range s.r.Accounts {
		switch {
		case !a.Enabled:
			invited = append(invited, map[string]any{
				"id": simInt("invitation", a.Key), "node_id": "node-invitation-" + a.Key, "login": s.login(a), "email": nil, "role": "direct_member",
				"created_at": s.at(1), "failed_at": nil, "failed_reason": nil, "team_count": 0, "invitation_source": "member",
				"inviter": user(s.r.Accounts[0]), "invitation_teams_url": s.orgURL("/invitations/" + strconv.FormatInt(simInt("invitation", a.Key), 10) + "/teams"),
			})
		case s.r.Terms.AccountKinds[a.Kind] == roster.KindMember:
			members = append(members, user(a))
			names = append(names, map[string]any{"login": s.login(a), "name": nil})
			if slices.ContainsFunc(a.Roles, func(role string) bool { return role == "admin" }) {
				owners = append(owners, user(a))
			}
			if !hasMFA(a) {
				membersOff = append(membersOff, user(a))
			}
			if s.r.VCS.SingleSignOn && sso(a) {
				var record any
				if scim {
					record = map[string]any{"groups": []any{}}
				}
				identities = append(identities, map[string]any{
					"samlIdentity": map[string]any{"nameId": s.login(a) + "@idp.example.com"},
					"scimIdentity": record,
					"user":         map[string]any{"login": s.login(a)},
				})
			}
		case s.r.Terms.AccountKinds[a.Kind] == roster.KindGuest:
			collaborators = append(collaborators, user(a))
			if !hasMFA(a) {
				collaboratorsOff = append(collaboratorsOff, user(a))
			}
			profile := map[string]any{"login": s.login(a), "id": simInt("user", a.Key), "node_id": "node-user-" + a.Key, "type": "User", "site_admin": false,
				"name": nil, "company": nil, "blog": "", "location": nil, "email": nil, "bio": nil, "public_repos": 0, "followers": 0, "following": 0,
				"html_url": "https://github.com/" + s.login(a), "created_at": s.at(400), "updated_at": s.at(30)}
			s.t.Get("github.users.get", kitAPI+"/users/"+s.login(a), simulate.Need{}, profile)
		}
	}
	page := simLinks{Size: simPageSize}
	members2FA := reads("members")
	s.t.List("github.org_members.list", s.orgURL("/members?per_page=100"), reads("members"), page, members)
	s.t.List("github.org_admins.list", s.orgURL("/members?role=admin&per_page=100"), reads("members"), page, owners)
	s.t.List("github.outside_collaborators.list", s.orgURL("/outside_collaborators?per_page=100"), reads("members"), page, collaborators)
	s.t.List("github.org_members_2fa_disabled.list", s.orgURL("/members?filter=2fa_disabled&per_page=100"), members2FA, page, membersOff)
	s.t.List("github.outside_collaborators_2fa_disabled.list", s.orgURL("/outside_collaborators?filter=2fa_disabled&per_page=100"), members2FA, page, collaboratorsOff)
	s.t.List("github.org_invitations.list", s.orgURL("/invitations?per_page=100"), reads("members"), page, invited)
	s.graphQL("github.member_names.list", reads("members"), "organization/membersWithRole", names)
	if !s.r.VCS.SingleSignOn {
		if _, refused := s.t.Refused(reads("members")); !refused {
			s.t.Add(collectortest.Response{Operation: "github.saml_identities.list", Method: http.MethodPost, URL: kitGraphQL,
				Body: simulate.JSON(map[string]any{"data": map[string]any{"organization": map[string]any{"samlIdentityProvider": nil}}})})
			return
		}
	}
	s.graphQL("github.saml_identities.list", reads("members"), "organization/samlIdentityProvider/externalIdentities", identities)
}

// installations answers the GitHub Apps installed on the organization.
func (s *githubSim) installations() {
	var items []any
	for _, a := range s.r.Apps {
		item := s.rec.Like("github.org_installations.list", "installations")
		slug := a.Key
		simulate.Extra(a.Extra, "slug", &slug)
		item["id"], item["app_id"], item["app_slug"], item["client_id"] = simInt("installation", a.Key), simInt("app", a.Key), slug, "client-"+a.Key
		if a.Key == "collector" {
			item["id"], item["app_id"] = kitInstallationID, kitAppID
			permissions := map[string]any{}
			for _, p := range s.granted {
				permissions[p] = "read"
			}
			item["permissions"], item["repository_selection"] = permissions, s.selection()
		}
		item["html_url"] = "https://github.com/organizations/" + kitOrg + "/settings/installations/" + strconv.FormatInt(simInt("installation", a.Key), 10)
		// GitHub also names who suspended an App, which the collector
		// doesn't read, and the recordings hold no suspended App.
		item["suspended_at"], item["suspended_by"] = nil, nil
		if !a.Enabled {
			item["suspended_at"] = s.at(10)
		}
		items = append(items, item)
	}
	s.t.List("github.org_installations.list", s.orgURL("/installations?per_page=100"), reads("organization_administration"),
		simLinks{Items: "installations", Envelope: map[string]any{"total_count": len(items)}, Size: simPageSize}, items)
}

// tokens answers the fine-grained personal access tokens approved for the
// organization. GitHub lists an expired token until it is revoked.
func (s *githubSim) tokens() {
	var items []any
	for _, m := range s.r.VCS.Credentials {
		if len(m.Repositories) > 0 {
			continue
		}
		owner, ok := s.r.Account(m.Owner)
		if !ok || m.CreatedDaysAgo != nil {
			panic("githubSim: token " + m.Key + " needs an owner, and GitHub reports no creation day for it")
		}
		var expires, lastUsed any
		if m.ExpiresInDays != nil {
			expires = s.at(-*m.ExpiresInDays)
		}
		if !m.Active {
			expires = s.at(1)
		}
		if m.LastUsedDaysAgo != nil {
			lastUsed = s.at(*m.LastUsedDaysAgo)
		}
		id := simInt("token grant", m.Key)
		items = append(items, map[string]any{
			"id": id, "owner": s.rec.Like("github.org_members.list", ""), "repository_selection": "all",
			"repositories_url":  s.orgURL("/personal-access-tokens/" + strconv.FormatInt(id, 10) + "/repositories"),
			"permissions":       map[string]any{"repository": map[string]any{"contents": s.permission(m)}, "organization": map[string]any{}},
			"access_granted_at": s.at(5), "token_id": simInt("token", m.Key), "token_name": m.Key, "token_expired": !m.Active,
			"token_expires_at": expires, "token_last_used_at": lastUsed,
		})
		simulate.Set(items[len(items)-1].(map[string]any), "owner/login", s.login(owner))
	}
	s.t.List("github.org_personal_access_tokens.list", s.orgURL("/personal-access-tokens?per_page=100"), reads("organization_personal_access_tokens"), simLinks{Size: simPageSize}, items)
}

// surfaces answers the organization's reads no normalized value comes
// from: webhooks, runners, Actions secrets, and the audit log, which needs
// GitHub Enterprise Cloud, as SAML single sign-on does.
func (s *githubSim) surfaces() {
	page := simLinks{Size: simPageSize}
	s.t.List("github.org_hooks.list", s.orgURL("/hooks?per_page=100"), reads("organization_hooks"), page, nil)
	s.t.List("github.org_runners.list", s.orgURL("/actions/runners?per_page=100"), reads("organization_self_hosted_runners"),
		simLinks{Items: "runners", Envelope: map[string]any{"total_count": 0}, Size: simPageSize}, nil)
	s.t.List("github.org_actions_secrets.list", s.orgURL("/actions/secrets?per_page=100"), reads("organization_secrets"),
		simLinks{Items: "secrets", Envelope: map[string]any{"total_count": 0}, Size: simPageSize}, nil)
	if s.r.VCS.SingleSignOn {
		s.t.List("github.audit_log.list", s.orgURL("/audit-log"), reads("organization_administration"), page, nil)
		return
	}
	s.fail("github.audit_log.list", s.orgURL("/audit-log"), reads("organization_administration"), http.StatusNotFound, "Not Found")
}

// simLinks pages a REST list as GitHub does: the bare list, or its items
// under Items beside the Envelope's fields, such as total_count, with the
// next and last pages in one Link header. GitHub numbers pages from 1 in
// the page parameter.
type simLinks struct {
	Items    string
	Envelope map[string]any
	Size     int
}

// Pages answers the list at first.
func (p simLinks) Pages(first string, items []any, size int) []collectortest.Response {
	size = cmp.Or(size, p.Size)
	pages := 1
	if size > 0 && len(items) > size {
		pages = (len(items) + size - 1) / size
	}
	at := func(n int) string {
		if n == 1 {
			return first
		}
		u, err := url.Parse(first)
		if err != nil {
			panic(err)
		}
		q := u.Query()
		q.Set("page", strconv.Itoa(n))
		u.RawQuery = q.Encode()
		return u.String()
	}
	var out []collectortest.Response
	for n := 1; n <= pages; n++ {
		lo, hi := 0, len(items)
		if pages > 1 {
			lo, hi = (n-1)*size, min(n*size, len(items))
		}
		var body any = items[lo:hi]
		if p.Items != "" {
			envelope := maps.Clone(p.Envelope)
			if envelope == nil {
				envelope = map[string]any{}
			}
			envelope[p.Items] = items[lo:hi]
			body = envelope
		}
		r := collectortest.Response{URL: at(n), Body: simulate.JSON(body)}
		if n < pages {
			r.Header = http.Header{"Link": {fmt.Sprintf(`<%s>; rel="next", <%s>; rel="last"`, at(n+1), at(pages))}}
		}
		out = append(out, r)
	}
	return out
}

// simGraphQLPages pages a GraphQL connection at Path, field names joined by
// /: each page holds its nodes and pageInfo, and the next request names the
// page's endCursor in the cursor variable.
type simGraphQLPages struct {
	Path string
	Size int
}

// Pages answers the connection's requests to first.
func (p simGraphQLPages) Pages(first string, items []any, size int) []collectortest.Response {
	size = cmp.Or(size, p.Size)
	var out []collectortest.Response
	var cursor any
	for lo := 0; lo == 0 || lo < len(items); lo += size {
		hi := min(lo+size, len(items))
		var end any
		if hi > lo {
			end = "cursor-" + strconv.Itoa(hi)
		}
		body := map[string]any{}
		simulate.Set(body, p.Path+"/nodes", items[lo:hi])
		simulate.Set(body, p.Path+"/pageInfo", map[string]any{"hasNextPage": hi < len(items), "endCursor": end})
		out = append(out, collectortest.Response{
			Method: http.MethodPost, URL: first, Body: simulate.JSON(body),
			RequestBody: simulate.JSON(map[string]any{"variables": map[string]any{"cursor": cursor}}),
		})
		cursor = end
	}
	return out
}

func nonNil(items []any) []any {
	if items == nil {
		return []any{}
	}
	return items
}
