package collector

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated organizations are rosters the GitHub simulator answers
// for, each with the values roster.Derive computes from it. A value the
// collector reports otherwise is listed with a verdict and a note that says
// where in the collector's code it was checked, so a new difference fails,
// and so does a listed one that goes away.

// simRosterPath is a sandbox's roster in v1 form, which cmd/derive in
// epack-collector-sandboxes converts from sandboxes/<name>/roster.json and
// the refresh workflow commits here.
func simRosterPath(name string) string { return "testdata/simulator/" + name + ".roster.json" }

// simConfig runs the collector at the audit level as the GitHub App, with
// the scan patterns of the roster's vcs block.
func simConfig(r *roster.Roster) map[string]any {
	config := kitConfig()
	config["level"] = "audit"
	delete(config, "exclude_patterns")
	for key, patterns := range map[string][]string{"include_patterns": r.VCS.IncludePatterns, "exclude_patterns": r.VCS.ExcludePatterns} {
		if len(patterns) > 0 {
			config[key] = simulate.Each(patterns, func(p string) any { return p })
		}
	}
	return config
}

// simArtifacts are the normalized artifacts the collector writes, with the
// schemas Derive gives values for.
var simArtifacts = []simulate.Artifact{
	{Schema: roster.VCSPosture, Path: NormalizedPath},
	{Schema: roster.AccessPosture, Prefix: "access-posture:", Path: AccessPath},
	{Schema: roster.VulnScanning, Prefix: "vuln-scanning:", Path: VulnPath},
}

// simHarness runs the collector against the simulated organization and
// checks each answer's shape against the sandboxes' recordings. The scan
// patterns are config, not answers, so Collect takes them from the roster
// Simulate last answered for.
func simHarness(t testing.TB, standing simulate.Differences) simulate.Harness {
	rec := simRecording(t)
	var config map[string]any
	return simulate.Harness{
		Simulate: func(r *roster.Roster, pageSize int) []collectortest.Response {
			config = simConfig(r)
			return newGitHubSim(r, rec, kitClock, pageSize).responses()
		},
		Collect: func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult {
			res := simulate.InProcess(t, Spec("test", "simulator"), Run, componentsdk.InProcessOptions{
				Config:  config,
				Secrets: kitSecrets(),
				Clock:   func() time.Time { return kitClock },
			}, responses)
			simScannerOrder(t, res)
			return res
		},
		Artifacts:  simArtifacts,
		Standing:   standing,
		Recorded:   rec,
		Unrecorded: simUnrecorded,
		Coverage:   true,
		Uncompared: simUncompared,
	}
}

// simScannerOrder lists the vuln-scanning artifact's scanners by name, and
// moves the gaps on them along. Derive lists them by the roster's names for
// them, which gives the same order, and the harness lines list entries up
// by index.
func simScannerOrder(t *testing.T, res componentsdk.InProcessResult) {
	t.Helper()
	for i, a := range res.Artifacts {
		if a.Path != VulnPath {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(a.Data, &doc); err != nil {
			t.Fatal(err)
		}
		scanners, _ := doc["scanners"].([]any)
		order := make([]int, len(scanners))
		for j := range order {
			order[j] = j
		}
		slices.SortStableFunc(order, func(x, y int) int {
			return compareStrings(scanners[x].(map[string]any)["scanner"], scanners[y].(map[string]any)["scanner"])
		})
		moved := map[string]string{}
		sorted := make([]any, len(scanners))
		for to, from := range order {
			sorted[to] = scanners[from]
			moved[fmt.Sprintf("/scanners/%d", from)] = fmt.Sprintf("/scanners/%d", to)
		}
		doc["scanners"] = sorted
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		res.Artifacts[i].Data = data
		if res.Result == nil {
			continue
		}
		for j, g := range res.Result.Gaps {
			if g.Path != VulnPath {
				continue
			}
			for from, to := range moved {
				if g.Pointer == from || strings.HasPrefix(g.Pointer, from+"/") {
					res.Result.Gaps[j].Pointer = to + strings.TrimPrefix(g.Pointer, from)
					break
				}
			}
		}
	}
}

func compareStrings(a, b any) int {
	x, _ := a.(string)
	y, _ := b.(string)
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// simUnrecorded lists the answers the sandboxes' recordings can't vouch
// for, with why.
var simUnrecorded = map[string]string{
	"github.org_members_2fa_disabled.list []: unrecorded field":                                                       "every sandbox member has two-factor authentication",
	"github.outside_collaborators.list []: unrecorded field":                                                          "the sandboxes have no outside collaborators",
	"github.users.get: unrecorded operation":                                                                          "the sandboxes have no outside collaborators, whose names the collector reads one at a time",
	"github.org_invitations.list []: unrecorded field":                                                                "the sandboxes have no pending invitation",
	"github.deploy_keys.list []: unrecorded field":                                                                    "the sandboxes have no deploy keys; the body follows GitHub's API reference",
	"github.org_personal_access_tokens.list: unrecorded operation":                                                    "the sandboxes' App lacks Personal access tokens (github-noncompliant's checklist step 8), so the recordings hold only the refusal; the body follows GitHub's API reference",
	"github.installation_token.create permissions.organization_personal_access_tokens: unrecorded field":              "the sandboxes' App lacks Personal access tokens",
	"github.org_installations.list installations[].permissions.organization_personal_access_tokens: unrecorded field": "the sandboxes' App lacks Personal access tokens",
	"github.installation_token.create permissions.administration: missing field":                                      "the sandboxes' App has Administration",
	"github.org_installations.list installations[].permissions.administration: missing field":                         "the sandboxes' App has Administration",
	"github.repos.get security_and_analysis: missing field":                                                           "the sandboxes' App has Administration, without which GitHub leaves the block out",
	"github.dependabot_alerts.list []: unrecorded field":                                                              "the sandboxes have no open alerts; the body follows GitHub's API reference",
	"github.code_scanning_alerts.list []: unrecorded field":                                                           "the sandboxes have no open alerts; the body follows GitHub's API reference",
	"github.secret_scanning_alerts.list []: unrecorded field":                                                         "the sandboxes have no open alerts; the body follows GitHub's API reference",
	"github.org_installations.list installations[].suspended_at: type":                                                "the sandboxes have no suspended App",
	"github.installation_token.create permissions.members: missing field":                                             "the sandboxes' App has Members",
	"github.org_installations.list installations[].permissions.members: missing field":                                "the sandboxes' App has Members",
	"github.installation_token.create permissions.organization_administration: missing field":                         "the sandboxes' App has Organization administration",
	"github.member_names.list data.organization.membersWithRole: type":                                                "the sandboxes' App has Members, without which GitHub answers FORBIDDEN with null data",
	"github.member_names.list errors: unrecorded field":                                                               "the sandboxes' App has Members, without which GitHub answers FORBIDDEN",
	"github.audit_log.list: unrecorded operation":                                                                     "the sandboxes have no GitHub Enterprise Cloud, which the audit log and SAML single sign-on need, so the recordings hold only the 404",
	"github.outside_collaborators_2fa_disabled.list: unrecorded operation":                                            "the sandboxes have no outside collaborators, so the collector never lists those without two-factor authentication",
	"github.saml_identities.list: unrecorded operation":                                                               "the sandboxes were recorded before the collector read SAML identities, and kitRecordingAnswers answers github-noncompliant's",
}

func init() {
	for _, field := range simOwnerOnly {
		for _, op := range []string{"github.orgs.get", "github.org_settings.get"} {
			simUnrecorded[op+" "+field+": missing field"] = "the sandboxes' App has Organization administration, without which GitHub shows only an organization's public fields"
		}
	}
}

// simUncompared lists the fields the collector writes that the rosters give
// no value for, with why.
var simUncompared = map[string]string{}

// simHiddenClassic are the differences when GitHub hides the classic
// protections, as it does from an App without Administration.
var simHiddenClassic = simulate.Same(simulate.Bug,
	"GitHub's GraphQL branchProtectionRule is null, with no error, for a caller without admin access, and branch_protection.go evaluateProtection reads a nil classic rule as none, so classic-pr-required counts as unprotected with no gap",
	"/branch_protection/pr_required_pct", "/branch_protection/pr_required_repository_count",
	"/branch_protection/approving_reviews_pct", "/branch_protection/approving_reviews_repository_count")

// simArchived are the differences an archived repository makes.
var simArchived = simulate.Same(simulate.Definition,
	"archived-repositories in the sandboxes' definitions.yaml: metrics.go processRepository leaves archived repositories out of scope, and Derive's scan covers them, since the schema makes no exception for them",
	"/scanned_repository_count", "/repo_coverage_pct",
	"/branch_protection/pr_required_pct", "/branch_protection/approving_reviews_pct",
	"/branch_protection/status_checks_pct", "/branch_protection/signed_commits_pct")

// simStanding are differences that hold wherever the collector reads the
// value. Each one the sandboxes' expectations list under derived has the
// same verdict there.
var simStanding = simulate.Same(simulate.Definition,
	"coverage-scope in the sandboxes' definitions.yaml: the coverage is over the repositories the scan covers (metrics.go featureRollup, vulns.go toVulnScanning), and Derive's over every repository the scanning block lists, archived, excluded and unreadable ones included",
	"/security_features/vuln_alerts_pct", "/security_features/code_scanning_pct", "/security_features/secret_scanning_pct",
	"vuln-scanning:/scanners/0/resource_count", "vuln-scanning:/scanners/0/scanned_resource_count", "vuln-scanning:/scanners/0/coverage_pct",
	"vuln-scanning:/scanners/1/resource_count", "vuln-scanning:/scanners/1/scanned_resource_count", "vuln-scanning:/scanners/1/coverage_pct",
	"vuln-scanning:/scanners/2/resource_count", "vuln-scanning:/scanners/2/scanned_resource_count", "vuln-scanning:/scanners/2/coverage_pct").With(
	simulate.Same(simulate.Gap, "unsupported: vulns.go toVulnScanning, since secret scanning alerts have no severity",
		"vuln-scanning:/scanners/2/open_critical_count", "vuln-scanning:/scanners/2/open_critical_present",
		"vuln-scanning:/scanners/2/open_high_count", "vuln-scanning:/scanners/2/open_high_present",
		"vuln-scanning:/scanners/2/open_medium_count", "vuln-scanning:/scanners/2/open_low_count",
		"vuln-scanning:/scanners/2/overdue_present", "vuln-scanning:/scanners/2/overdue_critical_count", "vuln-scanning:/scanners/2/overdue_high_count"),
	simulate.Same(simulate.Gap, "not_read: access.go toAccessPosture, since GitHub shows whether SAML single sign-on is required only to enterprise owners",
		"access-posture:/sign_in/sso_required"),
	simulate.Same(simulate.Gap, "unsupported: access.go toAccessPosture, since member records carry no sign-in time",
		"access-posture:/members/inactive_member_count", "access-posture:/members/inactive_pct"),
	simulate.Same(simulate.Gap,
		"not_read: access.go countPeople, below the admin base permission, since a member can be an admin through an organization role, which the collector does not read; the sandboxes' expectations call it a bug, opened 2026-11-12, and reading the roles needs the Custom organization roles permission",
		"access-posture:/admins/admin_count", "access-posture:/admins/admin_share_pct", "access-posture:/admins/local_admin_count",
		"access-posture:/admins/local_mfa_admin_count", "access-posture:/admins/local_admin_mfa_coverage_pct"),
	simulate.Same(simulate.Gap, "permission_denied: access.go accessCredentials, when the collector app lacks Personal access tokens, as the sandboxes' does",
		"access-posture:/credentials/credentials_present", "access-posture:/credentials/credential_count",
		"access-posture:/credentials/never_expiring_credential_count", "access-posture:/credentials/never_expiring_pct",
		"access-posture:/credentials/unused_credential_count", "access-posture:/credentials/unused_pct",
		"access-posture:/credentials/unrestricted_credential_count", "access-posture:/credentials/unrestricted_pct",
		"access-posture:/credentials/write_access_credential_count", "access-posture:/credentials/write_access_pct",
		"access-posture:/credentials/rotation_overdue_credential_count", "access-posture:/credentials/rotation_overdue_pct"),
	simulate.Same(simulate.Definition,
		"own-apps-connected in the sandboxes' definitions.yaml: access.go activeInstallations counts every installation that is not suspended, the collector's own App among them, and Derive only apps another account publishes",
		"access-posture:/connected_apps/app_count", "access-posture:/connected_apps/apps_present"),
)

func simBase(t testing.TB, name string) *roster.Roster {
	t.Helper()
	r, err := roster.Load(simRosterPath(name))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func validated(t testing.TB, r *roster.Roster) *roster.Roster {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func simScenarios(t testing.TB) []simulate.Scenario {
	t.Helper()
	var out []simulate.Scenario
	out = append(out, simulate.Realizations(t, "github-compliant", simBase(t, "github-compliant"), simArchived)...)
	out = append(out, simulate.Realizations(t, "github-noncompliant", simBase(t, "github-noncompliant"), nil)...)
	compliant, noncompliant := simSettled(t, "github-compliant"), simSettled(t, "github-noncompliant")
	out = append(out,
		simulate.Scenario{Name: "members, an outside collaborator and an invitation", Roster: validated(t, withPeople(noncompliant))},
		simulate.Scenario{Name: "admin base permission", Roster: validated(t, withBasePermission(withPeople(noncompliant), "admin"))},
		simulate.Scenario{Name: "write base permission", Roster: validated(t, withBasePermission(withPeople(noncompliant), "write"))},
		simulate.Scenario{Name: "deploy keys and fine-grained tokens", Roster: validated(t, withCredentials(noncompliant))},
		simulate.Scenario{Name: "SAML single sign-on with SCIM", Roster: validated(t, withSAML(withPeople(compliant))), Differences: simArchived},
		simulate.Scenario{Name: "open alerts", Roster: validated(t, withAlerts(noncompliant))},
		simulate.Scenario{Name: "collector app without Administration", Roster: validated(t, withoutPermission(noncompliant, "administration")), Differences: simHiddenClassic.With(
			simulate.Same(simulate.Gap, "permission_denied: client.go FetchSecuritySettings and checkDefaultSetup, since GitHub shows security_and_analysis and code scanning default setup only with Administration",
				"/security_features/code_scanning_pct", "/security_features/secret_scanning_pct",
				"vuln-scanning:/scanners/0/enabled", "vuln-scanning:/scanners/0/coverage_pct", "vuln-scanning:/scanners/0/scanned_resource_count",
				"vuln-scanning:/scanners/2/enabled", "vuln-scanning:/scanners/2/coverage_pct", "vuln-scanning:/scanners/2/scanned_resource_count"))},
	)
	return out
}

// simSettled is a sandbox's roster with its unsettled attributes as its
// first realization has them.
func simSettled(t testing.TB, name string) *roster.Roster {
	t.Helper()
	reals, err := simBase(t, name).Realizations()
	if err != nil {
		t.Fatal(err)
	}
	return reals[0].Roster
}

func intPtr(n int) *int { return &n }

// withPeople adds a member without two-factor authentication who signed in
// a week ago, an outside collaborator with it, and an invited person.
func withPeople(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	r.Accounts = append(r.Accounts,
		roster.Account{Key: "member_no_2fa", Kind: "member", Enabled: true, Roles: []string{"member"}, Logins: []string{"password"}, SignedInDaysAgo: intPtr(7)},
		roster.Account{Key: "contractor", Kind: "outside_collaborator", Enabled: true, Methods: []string{"two_factor"}, Logins: []string{"password"}, SignedInDaysAgo: intPtr(2)},
		roster.Account{Key: "invitee", Kind: "member", Roles: []string{"member"}, Logins: []string{"password"}},
	)
	return r
}

// withBasePermission sets the members' base permission on every
// repository. read, write and none make no one an admin.
func withBasePermission(base *roster.Roster, permission string) *roster.Roster {
	r := base.Clone()
	r.VCS.BasePermission = permission
	r.Terms.Roles = maps.Clone(r.Terms.Roles)
	for _, p := range []string{"read", "write", "none"} {
		r.Terms.Roles[p] = roster.RoleNone
	}
	return r
}

// withPermission gives the collector app another permission.
func withPermission(base *roster.Roster, permission string) *roster.Roster {
	r := base.Clone()
	simulate.OnApp("collector", func(a *roster.App) {
		simulate.SetExtra(&a.Extra, "permissions", append(slices.Clone(simPermissions), permission))
	})(r)
	return r
}

// withoutPermission takes a permission from the collector app.
func withoutPermission(base *roster.Roster, permission string) *roster.Roster {
	r := base.Clone()
	held := slices.DeleteFunc(slices.Clone(simPermissions), func(p string) bool { return p == permission })
	simulate.OnApp("collector", func(a *roster.App) { simulate.SetExtra(&a.Extra, "permissions", held) })(r)
	return r
}

// simCredentialTerms map a credential's GitHub access to normalized
// permissions.
var simCredentialTerms = map[string]string{"read": roster.PermissionsRead, "write": roster.PermissionsWrite}

// withCredentials gives the collector app Personal access tokens, and the
// organization a read-write deploy key added 200 days ago and used
// yesterday, a read-only one added 10 days ago and never used, one on a
// repository the scan leaves out, a token that expires in 30 days, one that
// never expires and was last used 120 days ago, all owned by the owner.
func withCredentials(base *roster.Roster) *roster.Roster {
	r := withPermission(base, "organization_personal_access_tokens")
	r.Terms.VCSCredentialPermissions = simCredentialTerms
	first := "classic-pr-required"
	r.VCS.Credentials = append(r.VCS.Credentials,
		roster.MachineCredential{Key: "deploy-rw", Repositories: []string{first}, Active: true, CreatedDaysAgo: intPtr(200), LastUsedDaysAgo: intPtr(1), Permissions: "write"},
		roster.MachineCredential{Key: "deploy-ro", Repositories: []string{first}, Active: true, CreatedDaysAgo: intPtr(10), Permissions: "read"},
		roster.MachineCredential{Key: "deploy-scratch", Repositories: []string{"scratch-notes"}, Active: true, CreatedDaysAgo: intPtr(5), Permissions: "read"},
		roster.MachineCredential{Key: "token-ci", Owner: "owner", Active: true, ExpiresInDays: intPtr(30), LastUsedDaysAgo: intPtr(3), Permissions: "write"},
		roster.MachineCredential{Key: "token-old", Owner: "owner", Active: true, LastUsedDaysAgo: intPtr(120), Permissions: "read"},
	)
	return r
}

// withSAML gives the organization SAML single sign-on with SCIM, which
// needs GitHub Enterprise Cloud, and links the owner's account to it.
func withSAML(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	r.VCS.SingleSignOn = true
	r.VCS.Provisioning = []string{"scim_create", "scim_deactivate"}
	r.Terms.ProvisioningFeatures = map[string]string{"scim_create": roster.ProvisionCreate, "scim_deactivate": roster.ProvisionDeactivate}
	simulate.OnAccount("owner", func(a *roster.Account) { a.Logins = []string{"password", "saml"} })(r)
	return r
}

// withAlerts opens alerts on classic-pr-required, which every scanner
// scans: Dependabot alerts of each severity, the critical one 31 days old
// and the high one 91, and a critical code scanning alert 31 days old.
func withAlerts(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	res := &r.Scanning.Resources[slices.IndexFunc(r.Scanning.Resources, func(res roster.ScanResource) bool { return res.Key == "classic-pr-required" })]
	res.Findings = append(slices.Clone(res.Findings),
		roster.VulnFinding{Key: "dep-critical", Scanner: "Dependabot alerts", Severity: "critical", State: "open", OpenDays: intPtr(31)},
		roster.VulnFinding{Key: "dep-high", Scanner: "Dependabot alerts", Severity: "high", State: "open", OpenDays: intPtr(91)},
		roster.VulnFinding{Key: "dep-medium", Scanner: "Dependabot alerts", Severity: "medium", State: "open", OpenDays: intPtr(5)},
		roster.VulnFinding{Key: "dep-low", Scanner: "Dependabot alerts", Severity: "low", State: "open", OpenDays: intPtr(5)},
		roster.VulnFinding{Key: "dep-fixed", Scanner: "Dependabot alerts", Severity: "critical", State: "fixed", OpenDays: intPtr(40)},
		roster.VulnFinding{Key: "code-critical", Scanner: "Code scanning", Severity: "critical", State: "open", OpenDays: intPtr(31)},
	)
	return r
}

func TestSimulatedOrgs(t *testing.T) {
	simHarness(t, simStanding).Tenants(t, simScenarios(t))
}

// TestSimulatedShapes checks the answers for every scenario and every
// one-at-a-time matrix row against the recordings, and that each
// simUnrecorded listing is still needed.
func TestSimulatedShapes(t *testing.T) {
	var rosters []*roster.Roster
	for _, sc := range simScenarios(t) {
		rosters = append(rosters, sc.Roster)
	}
	axes := simMatrixAxes()
	for _, row := range roster.OneAtATime(axes) {
		v, err := roster.Build(simMatrixBase(t), axes, row)
		if err != nil {
			t.Fatal(err)
		}
		rosters = append(rosters, v.Roster)
	}
	simHarness(t, simStanding).CheckRecorded(t, rosters...)
}

// simKitConfig is the kit suite's configuration, which each scenario's scan
// patterns add to.
func simKitConfig() map[string]any {
	config := kitConfig()
	config["level"] = "audit"
	delete(config, "exclude_patterns")
	return config
}

// TestSimulatedOrgsKit runs the kit's checks over the simulated
// organizations: the fault matrix and the rest on the first baseline, and
// each scenario's derived values, less the listed differences, as Expect.
func TestSimulatedOrgsKit(t *testing.T) {
	h := simHarness(t, simStanding)
	var scenarios []collectortest.Scenario
	for _, sc := range simScenarios(t) {
		config := simConfig(sc.Roster)
		for key := range simKitConfig() {
			delete(config, key)
		}
		scenarios = append(scenarios, collectortest.Scenario{
			Name:      sc.Name,
			Config:    config,
			Responses: h.Simulate(sc.Roster, 0),
			Expect:    simCollectorOrder(h.Expect(t, sc)),
		})
	}
	s := kitSuite()
	s.Name = "github-simulated"
	// No simulated organization has deployment environments, whose
	// policies and rules the kit suite reaches.
	s.Operations = slices.DeleteFunc(slices.Clone(kitOperations), func(op string) bool {
		return op == "github.environment_branch_policies.list" || op == "github.environment_protection_rules.list"
	})
	s.Spec = Spec("test", "collectortest")
	// The sensitivity check flips booleans, adds to numbers and empties
	// lists. In these answers, copies of recorded ones, the collector reads
	// only strings, such as a ruleset's enforcement, the default setup's
	// state and the security_and_analysis statuses, and the members' names,
	// which the simulated members leave unset.
	s.Insensitive = append(slices.Clone(s.Insensitive), "github.repos.get", "github.code_scanning_default_setup.get", "github.rulesets.get", "github.member_names.list")
	s.Config = simKitConfig()
	s.Scenarios = scenarios
	collectortest.Run(t, s)
}

// simCollectorOrder renumbers the vuln-scanning scanners in expectations
// from Derive's order, by name, to the collector's, since the kit's runs
// read the artifact as the collector writes it.
func simCollectorOrder(expect map[string]map[string]any) map[string]map[string]any {
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.name
	}
	sorted := slices.Sorted(slices.Values(names))
	out := map[string]any{}
	for pointer, v := range expect[VulnPath] {
		rest, ok := strings.CutPrefix(pointer, "/scanners/")
		if !ok {
			out[pointer] = v
			continue
		}
		index, field, _ := strings.Cut(rest, "/")
		i, err := strconv.Atoi(index)
		if err != nil || i >= len(sorted) {
			out[pointer] = v
			continue
		}
		out[fmt.Sprintf("/scanners/%d/%s", slices.Index(names, sorted[i]), field)] = v
	}
	expect[VulnPath] = out
	return expect
}

// TestSimulatorMatchesRecording compares the simulator's answers for each
// sandbox's roster with the sandbox's recording, so a field, type, count,
// or vocabulary value the simulator gets wrong fails when a new recording
// comes in. Every GraphQL call goes to one URL, so both sides carry the
// operation in it.
func TestSimulatorMatchesRecording(t *testing.T) {
	for _, name := range simRecordingNames {
		t.Run(name, func(t *testing.T) {
			simulate.CheckRecording(t, simulate.Recording{
				Path: simTaggedRecording(t, name),
				Options: collectortest.CompareOptions{
					Vocabulary: simRecordingVocabulary,
				},
				Rewrite: simRewriteURL,
				Known:   simRecordingKnown[name],
				Simulate: func(t *testing.T, recordedAt time.Time) []collectortest.Response {
					return simTagged(newGitHubSim(simSettled(t, name), simRecording(t), recordedAt, 0).responses())
				},
			})
		})
	}
}

// simTagged adds each GraphQL call's operation to its URL.
func simTagged(responses []collectortest.Response) []collectortest.Response {
	out := slices.Clone(responses)
	for i, r := range out {
		if r.URL == kitGraphQL {
			out[i].URL = kitGraphQL + "?operation=" + r.Operation
		}
	}
	return out
}

// simTaggedRecording writes a copy of a sandbox's recording with each
// GraphQL call's operation in its URL.
func simTaggedRecording(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(simRecordingPath(name))
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	responses, _ := rec["responses"].([]any)
	for _, r := range responses {
		m := r.(map[string]any)
		if m["url"] == kitGraphQL+"?" || m["url"] == kitGraphQL {
			m["url"] = kitGraphQL + "?operation=" + m["operation"].(string)
		}
	}
	path := filepath.Join(t.TempDir(), name+".json")
	if err := os.WriteFile(path, []byte(simulate.JSON(rec)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// simRulesetID is a ruleset's ID in a URL's path, which differs between the
// sandbox and the simulator.
var simRulesetID = regexp.MustCompile(`/rulesets/[0-9]+`)

// simRewriteURL replaces ruleset IDs, and drops the queries the recordings
// were made without, or with another time in them: the alert lists, which
// the collector filters since the recordings, and the audit log's start.
func simRewriteURL(u string) string {
	u = simRulesetID.ReplaceAllString(u, "/rulesets/{id}")
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	for _, suffix := range []string{"/alerts", "/audit-log"} {
		if strings.HasSuffix(parsed.Path, suffix) {
			parsed.RawQuery = ""
			return parsed.String()
		}
	}
	return u
}

// simRecordingVocabulary are the fields whose values the simulator takes
// from GitHub's documentation: states, types, selections and permissions.
var simRecordingVocabulary = []string{
	"repository_selection", "[].type", "[].ruleset_source_type", "enforcement", "rules[].type", "source_type", "state",
	"security_and_analysis.secret_scanning.status", "data.organization.repositories.nodes[].visibility",
}

// simRecordingKnown lists, by sandbox, the ways the simulator is known to
// differ from its recording, with why each is left.
var simRecordingKnown = map[string]map[string]string{
	"github-compliant": {
		"POST api.github.com/app/installations/78901234/access_tokens permissions.actions: extra (recorded nothing, simulated string)":                                            simTrustApp,
		"POST api.github.com/app/installations/78901234/access_tokens permissions.organization_hooks: extra (recorded nothing, simulated string)":                                 simTrustApp,
		"POST api.github.com/app/installations/78901234/access_tokens permissions.organization_secrets: extra (recorded nothing, simulated string)":                               simTrustApp,
		"POST api.github.com/app/installations/78901234/access_tokens permissions.organization_self_hosted_runners: extra (recorded nothing, simulated string)":                   simTrustApp,
		"POST api.github.com/app/installations/78901234/access_tokens permissions.repository_hooks: extra (recorded nothing, simulated string)":                                   simTrustApp,
		"POST api.github.com/graphql?operation=github.repositories.list data.organization.repositories.nodes[].primaryLanguage: type (recorded null or object, simulated object)": simLanguage,
	},
	"github-noncompliant": {
		"GET api.github.com/installation/repositories?per_page=100 repositories[].language: type (recorded null or string, simulated string)":                                     simLanguage,
		"POST api.github.com/graphql?operation=github.repositories.list data.organization.repositories.nodes[].primaryLanguage: type (recorded null or object, simulated object)": simLanguage,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/analyses?per_page=1: status (recorded 200, simulated 404)":                                       simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/analyses?per_page=1 []: missing (recorded object, simulated nothing)":                            simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/analyses?per_page=1 documentation_url: extra (recorded nothing, simulated string)":               simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/analyses?per_page=1 message: extra (recorded nothing, simulated string)":                         simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/analyses?per_page=1 status: extra (recorded nothing, simulated string)":                          simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/default-setup runner_label: type (recorded null, simulated string)":                              simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/default-setup schedule: type (recorded null, simulated string)":                                  simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/default-setup updated_at: type (recorded null, simulated string)":                                simWorkflowScan,
		"GET api.github.com/repos/test-org/ruleset-pr-no-approvals/code-scanning/default-setup state: values (recorded not-configured, simulated configured)":                     simWorkflowScan,
	},
}

const (
	simTrustApp     = "github-compliant's App has the trust-level permissions (its checklist step 6), and the simulator's App the audit-level ones, since the roster doesn't list them"
	simLanguage     = "each simulated repository copies a recorded one that has a language, and the roster doesn't say which repositories have none"
	simWorkflowScan = "ruleset-pr-no-approvals scans with a CodeQL workflow (checklist step 5), and the sandbox's roster gives code scanning as configured without saying how, so the simulator answers with default setup"
)
