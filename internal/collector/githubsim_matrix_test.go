package collector

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated matrix varies github-noncompliant along the axes below.
// Each one-at-a-time row changes one setting, so a difference it shows
// belongs to that setting and is listed in simMatrixAlone. The pairwise rows
// put every two settings together at least once, and a difference none of
// a row's settings shows alone must be listed in simMatrixTogether.

// simMatrixMember is a member the matrix adds, with two-factor
// authentication, who signs in with a password and signed in three days
// ago.
const simMatrixMember = "matrix_member"

// simMatrixRepo is a repository the matrix adds, in scope, unprotected,
// and with every scanner off.
const simMatrixRepo = "matrix-repo"

// simMatrixBase is github-noncompliant with the matrix's member and
// repository, the terms its axes use, and a collector app that also holds
// Personal access tokens, so the credential values are compared.
func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	r := withBasePermission(withPermission(simSettled(t, "github-noncompliant"), "organization_personal_access_tokens"), "")
	r.Terms.VCSCredentialPermissions = simCredentialTerms
	r.Terms.ProvisioningFeatures = map[string]string{"scim_create": roster.ProvisionCreate, "scim_deactivate": roster.ProvisionDeactivate}
	r.Accounts = append(r.Accounts, roster.Account{
		Key: simMatrixMember, Kind: "member", Enabled: true, Roles: []string{"member"}, Methods: []string{"two_factor"},
		Logins: []string{"password"}, SignedInDaysAgo: intPtr(3),
	})
	r.VCS.Repositories = append(r.VCS.Repositories, roster.Repository{Key: simMatrixRepo})
	r.Scanning.Resources = append(r.Scanning.Resources, roster.ScanResource{Key: simMatrixRepo, Type: "repository", Scans: map[string]string{
		"Dependabot alerts": "disabled", "Code scanning": "not-configured", "Secret scanning": "disabled",
	}})
	return validated(t, r)
}

func onMember(change func(*roster.Account)) func(*roster.Roster) {
	return simulate.OnAccount(simMatrixMember, change)
}

func onRepo(change func(*roster.Repository)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.VCS.Repositories {
			if r.VCS.Repositories[i].Key == simMatrixRepo {
				change(&r.VCS.Repositories[i])
			}
		}
	}
}

func onScans(change func(*roster.ScanResource)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Scanning.Resources {
			if r.Scanning.Resources[i].Key == simMatrixRepo {
				res := &r.Scanning.Resources[i]
				res.Scans = maps2(res.Scans)
				change(res)
			}
		}
	}
}

// maps2 copies a scan map, which a clone shares with its base.
func maps2(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// protect gives the matrix repository one protection.
func protect(key, enforcement string, extra map[string]any, rules ...roster.BranchRule) func(*roster.Roster) {
	return onRepo(func(repo *roster.Repository) {
		p := roster.BranchProtection{Key: key, Enforcement: enforcement, Rules: rules}
		for name, v := range extra {
			simulate.SetExtra(&p.Extra, name, v)
		}
		repo.Protections = append(slices.Clone(repo.Protections), p)
	})
}

// alert opens a finding on the matrix repository, and turns its scanner
// on, since GitHub lists alerts only from a scanner that scans.
func alert(scanner, on, severity, state string, days int) func(*roster.Roster) {
	return onScans(func(res *roster.ScanResource) {
		if res.Scans[scanner] != on && res.Scans[scanner] != "configured" {
			res.Scans[scanner] = on
		}
		res.Findings = append(slices.Clone(res.Findings), roster.VulnFinding{Key: "matrix", Scanner: scanner, Severity: severity, State: state, OpenDays: intPtr(days)})
	})
}

// credential adds a credential, a deploy key on the matrix repository when
// it has no owner.
func credential(c roster.MachineCredential) func(*roster.Roster) {
	return func(r *roster.Roster) {
		c.Key = "matrix-" + c.Permissions
		if c.Owner == "" {
			c.Repositories = []string{simMatrixRepo}
		}
		r.VCS.Credentials = append(slices.Clone(r.VCS.Credentials), c)
	}
}

// app installs another GitHub App.
func app(publisher string, enabled bool) func(*roster.Roster) {
	return func(r *roster.Roster) {
		r.Apps = append(slices.Clone(r.Apps), roster.App{Key: "matrix-app", Enabled: enabled, Publisher: publisher})
	}
}

// sso gives the organization SAML single sign-on, and links the matrix
// member when linked is set and it is a member, since GitHub links only
// members to the identity provider.
func sso(linked, scim bool) func(*roster.Roster) {
	return func(r *roster.Roster) {
		r.VCS.SingleSignOn = true
		if scim {
			r.VCS.Provisioning = []string{"scim_create", "scim_deactivate"}
		}
		if linked {
			onMember(func(a *roster.Account) {
				if a.Kind == "member" {
					a.Logins = []string{"password", "saml"}
				}
			})(r)
		}
	}
}

func simMatrixAxes() []roster.Axis {
	basePermission := func(p string) func(*roster.Roster) { return func(r *roster.Roster) { r.VCS.BasePermission = p } }
	drop := func(permission string) func(*roster.Roster) {
		return simulate.OnApp("collector", func(a *roster.App) {
			var held []string
			simulate.Extra(a.Extra, "permissions", &held)
			simulate.SetExtra(&a.Extra, "permissions", slices.DeleteFunc(slices.Clone(held), func(p string) bool { return p == permission }))
		})
	}
	return []roster.Axis{
		{Name: "base_permission", Values: []roster.Value{
			{Name: "default"},
			{Name: "none", Change: basePermission("none")},
			{Name: "write", Change: basePermission("write")},
			{Name: "admin", Change: basePermission("admin")},
		}},
		{Name: "member.kind", Values: []roster.Value{
			{Name: "member"},
			{Name: "owner", Change: onMember(func(a *roster.Account) { a.Roles = []string{"admin"} })},
			{Name: "outside collaborator", Change: onMember(func(a *roster.Account) { a.Kind, a.Roles = "outside_collaborator", nil })},
			{Name: "invited", Change: onMember(func(a *roster.Account) { a.Enabled, a.SignedInDaysAgo = false, nil })},
		}},
		{Name: "member.mfa", Values: []roster.Value{
			{Name: "two-factor"},
			{Name: "none", Change: onMember(func(a *roster.Account) { a.Methods = nil })},
		}},
		{Name: "member.sso", Values: []roster.Value{
			{Name: "password"},
			{Name: "linked to SAML", Change: sso(true, false)},
			{Name: "linked to SAML with SCIM", Change: sso(true, true)},
			{Name: "not linked to SAML", Change: sso(false, false)},
		}},
		// GitHub removes the members and outside collaborators without
		// two-factor authentication when the requirement is turned on, so
		// it comes after the member's methods.
		{Name: "two_factor_requirement", Values: []roster.Value{
			{Name: "off"},
			{Name: "on", Change: func(r *roster.Roster) {
				r.VCS.TwoFactorRequirement = true
				for i := range r.Accounts {
					if len(r.Accounts[i].Methods) == 0 {
						r.Accounts[i].Methods = []string{"two_factor"}
					}
				}
			}},
		}},
		{Name: "repo.state", Values: []roster.Value{
			{Name: "in scope"},
			{Name: "archived", Change: onRepo(func(repo *roster.Repository) { simulate.SetExtra(&repo.Extra, "archived", true) })},
			{Name: "excluded", Change: func(r *roster.Roster) {
				r.VCS.ExcludePatterns = append(slices.Clone(r.VCS.ExcludePatterns), "matrix-*")
			}},
			{Name: "private, App not installed", Change: onRepo(func(repo *roster.Repository) {
				repo.Unreadable = true
				simulate.SetExtra(&repo.Extra, "visibility", "private")
			})},
		}},
		{Name: "repo.protection", Values: []roster.Value{
			{Name: "none"},
			{Name: "classic, pull request with 1 approval", Change: protect("classic", "active", nil, roster.BranchRule{Type: "required_pull_request_reviews", Approvals: 1})},
			{Name: "classic, pull request with no approvals", Change: protect("classic", "active", nil, roster.BranchRule{Type: "required_pull_request_reviews"})},
			{Name: "classic, status checks naming build", Change: protect("classic", "active", nil, roster.BranchRule{Type: "required_status_checks", Checks: []string{"build"}})},
			{Name: "classic, status checks naming none", Change: protect("classic", "active", nil, roster.BranchRule{Type: "required_status_checks"})},
			{Name: "classic, signed commits", Change: protect("classic", "active", nil, roster.BranchRule{Type: "required_signatures"})},
			{Name: "ruleset, status checks naming none", Change: protect("ruleset:matrix", "active", nil, roster.BranchRule{Type: "required_status_checks"})},
			{Name: "ruleset, pull request with 2 approvals", Change: protect("ruleset:matrix", "active", nil, roster.BranchRule{Type: "pull_request", Approvals: 2})},
			{Name: "ruleset, pull request, evaluate", Change: protect("ruleset:matrix", "evaluate", nil, roster.BranchRule{Type: "pull_request", Approvals: 1})},
			{Name: "ruleset, pull request, disabled", Change: protect("ruleset:matrix", "disabled", nil, roster.BranchRule{Type: "pull_request", Approvals: 1})},
			{Name: "organization ruleset, status checks and signed commits", Change: protect("ruleset:org-matrix", "active", map[string]any{"source": "organization"},
				roster.BranchRule{Type: "required_status_checks", Checks: []string{"build"}}, roster.BranchRule{Type: "required_signatures"})},
		}},
		{Name: "repo.dependabot", Values: []roster.Value{
			{Name: "off"},
			{Name: "on", Change: onScans(func(res *roster.ScanResource) { res.Scans["Dependabot alerts"] = "enabled" })},
		}},
		{Name: "repo.code_scanning", Values: []roster.Value{
			{Name: "off"},
			{Name: "default setup", Change: onScans(func(res *roster.ScanResource) { res.Scans["Code scanning"] = "configured" })},
			{Name: "advanced setup", Change: func(r *roster.Roster) {
				onScans(func(res *roster.ScanResource) { res.Scans["Code scanning"] = "configured" })(r)
				onRepo(func(repo *roster.Repository) { simulate.SetExtra(&repo.Extra, "code_scanning_setup", "advanced") })(r)
			}},
		}},
		{Name: "repo.secret_scanning", Values: []roster.Value{
			{Name: "off"},
			{Name: "on", Change: onScans(func(res *roster.ScanResource) { res.Scans["Secret scanning"] = "enabled" })},
		}},
		// An alert turns its scanner on, so it comes after the scanners.
		{Name: "repo.alert", Values: []roster.Value{
			{Name: "none"},
			{Name: "Dependabot critical, 31 days", Change: alert("Dependabot alerts", "enabled", "critical", "open", 31)},
			{Name: "Dependabot high, 90 days", Change: alert("Dependabot alerts", "enabled", "high", "open", 90)},
			{Name: "Dependabot high, 91 days", Change: alert("Dependabot alerts", "enabled", "high", "open", 91)},
			{Name: "Dependabot critical, fixed", Change: alert("Dependabot alerts", "enabled", "critical", "fixed", 40)},
			{Name: "code scanning high, 91 days", Change: alert("Code scanning", "configured", "high", "open", 91)},
			{Name: "code scanning without a security severity", Change: alert("Code scanning", "configured", "", "open", 5)},
			{Name: "secret scanning", Change: alert("Secret scanning", "enabled", "", "open", 5)},
		}},
		{Name: "credential", Values: []roster.Value{
			{Name: "none"},
			{Name: "deploy key, read-write, used yesterday, 200 days old", Change: credential(roster.MachineCredential{Active: true, CreatedDaysAgo: intPtr(200), LastUsedDaysAgo: intPtr(1), Permissions: "write"})},
			{Name: "deploy key, read-only, never used, 10 days old", Change: credential(roster.MachineCredential{Active: true, CreatedDaysAgo: intPtr(10), Permissions: "read"})},
			{Name: "deploy key, disabled", Change: credential(roster.MachineCredential{CreatedDaysAgo: intPtr(30), LastUsedDaysAgo: intPtr(20), Permissions: "read"})},
			{Name: "token, expires in 30 days, used 3 days ago", Change: credential(roster.MachineCredential{Owner: "owner", Active: true, ExpiresInDays: intPtr(30), LastUsedDaysAgo: intPtr(3), Permissions: "write"})},
			{Name: "token, never expires, never used", Change: credential(roster.MachineCredential{Owner: "owner", Active: true, Permissions: "read"})},
			{Name: "token, expired", Change: credential(roster.MachineCredential{Owner: "owner", LastUsedDaysAgo: intPtr(40), Permissions: "read"})},
		}},
		{Name: "app", Values: []roster.Value{
			{Name: "collector only"},
			{Name: "third party", Change: app("other_account", true)},
			{Name: "third party, suspended", Change: app("other_account", false)},
			{Name: "this organization's", Change: app("this_organization", true)},
		}},
		{Name: "collector.permissions", Values: []roster.Value{
			{Name: "all"},
			{Name: "without Administration", Change: drop("administration")},
			{Name: "without Members", Change: drop("members")},
			{Name: "without Organization administration", Change: drop("organization_administration")},
			{Name: "without Personal access tokens", Change: drop("organization_personal_access_tokens")},
		}},
	}
}

// simMatrixAlone lists, by setting, the values the collector reports
// otherwise when that setting alone changes.
var simMatrixAlone = map[string]simulate.Differences{
	// No other repository requires status checks or signed commits, so
	// those shares are 0 either way.
	"repo.state=archived": simArchived.Without("/branch_protection/status_checks_pct", "/branch_protection/signed_commits_pct"),
	"repo.protection=classic, status checks naming none": simulate.Same(simulate.Bug,
		"repositoriesQuery reads requiresStatusChecks and not the checks the rule names, and branch_protection.go supplyClassic counts the rule, so a branch that requires no check counts as requiring status checks; whether GitHub keeps a classic rule that names no check is unconfirmed",
		"/branch_protection/status_checks_pct", "/branch_protection/status_checks_repository_count"),
	"collector.permissions=without Administration": simHiddenClassic.With(simulate.Same(simulate.Gap,
		"permission_denied: client.go FetchSecuritySettings and checkDefaultSetup, since GitHub shows security_and_analysis and code scanning default setup only with Administration",
		"vuln-scanning:/scanners/0/enabled", "vuln-scanning:/scanners/2/enabled")),
	"collector.permissions=without Members": simulate.Same(simulate.Gap, "permission_denied: surfaces.go GetOrgRosters and sso.go FetchOrgSSO need Members",
		"access-posture:/admins/admins_present", "access-posture:/admins/local_admins_present",
		"access-posture:/members/external_member_count", "access-posture:/members/external_members_present",
		"access-posture:/members/local_member_count", "access-posture:/members/local_members_present",
		"access-posture:/members/local_mfa_coverage_pct", "access-posture:/members/local_mfa_member_count",
		"access-posture:/members/member_count", "access-posture:/members/members_present",
		"access-posture:/members/sso_coverage_pct", "access-posture:/members/sso_member_count",
		"access-posture:/sign_in/scim_enabled", "access-posture:/sign_in/sso_configured"),
	"collector.permissions=without Organization administration": simulate.Same(simulate.Gap,
		"permission_denied: GitHub shows two_factor_requirement_enabled and owned_private_repos only with Organization administration, and an App on selected repositories needs GitHub's count of the organization's repositories (collector.go organizationRepositoryCount)",
		"/org_security/two_factor_required", "/repo_coverage_pct", "/repository_count", "access-posture:/sign_in/mfa_required"),
}

// simMatrixTogether lists the differences that show only when settings
// meet.
var simMatrixTogether = []simulate.Together{
	{
		Match: func(c []string) bool { return simulate.Any(c, "repo.state=archived") },
		Differences: simulate.Same(simulate.Definition,
			"archived-repositories in the sandboxes' definitions.yaml: the archived repository's protections and deploy keys count in Derive's scan, and metrics.go processRepository leaves the repository out",
			"/branch_protection/pr_required_repository_count", "/branch_protection/approving_reviews_repository_count",
			"/branch_protection/status_checks_repository_count", "/branch_protection/signed_commits_repository_count").With(simArchived, simCredentialPointers(simulate.Definition,
			"archived-repositories in the sandboxes' definitions.yaml: Derive counts a deploy key of an archived repository, and the collector reads the deploy keys of the repositories in scope")),
	},
	{
		Match: func(c []string) bool {
			return simulate.Any(c, "collector.permissions=without Administration") && slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "repo.protection=classic") })
		},
		Differences: simHiddenClassic,
	},
	{
		Match: func(c []string) bool {
			return slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "repo.alert=") }) &&
				slices.ContainsFunc(c, func(s string) bool { return strings.HasPrefix(s, "repo.state=") })
		},
		Differences: simAlertPointers(simulate.Definition,
			"coverage-scope in the sandboxes' definitions.yaml: Derive counts the open findings of every repository the scanning block lists, and the collector the open alerts of the repositories its scan covers"),
	},
	{
		Match: func(c []string) bool {
			return simulate.Any(c, "member.sso=linked to SAML with SCIM") && simulate.Any(c, "member.kind=invited", "member.kind=outside collaborator")
		},
		Differences: simulate.Same(simulate.Known,
			"docs/schema/methods.json: scim_enabled is true when a member's SAML identity has a SCIM record, and no member has one here, while Derive takes the organization's SCIM provisioning",
			"access-posture:/sign_in/scim_enabled"),
	},
}

// simCredentialPointers lists the credential values for one reason.
func simCredentialPointers(v simulate.Verdict, note string) simulate.Differences {
	var pointers []string
	for _, field := range []string{"credentials_present", "credential_count", "never_expiring_credential_count", "never_expiring_pct",
		"unused_credential_count", "unused_pct", "unrestricted_credential_count", "unrestricted_pct",
		"write_access_credential_count", "write_access_pct", "rotation_overdue_credential_count", "rotation_overdue_pct"} {
		pointers = append(pointers, "access-posture:/credentials/"+field)
	}
	return simulate.Same(v, note, pointers...)
}

// simAlertPointers lists the open and overdue alert values of the scanners
// with severities, code scanning and Dependabot, for one reason.
func simAlertPointers(v simulate.Verdict, note string) simulate.Differences {
	var pointers []string
	for _, scanner := range []string{"0", "1"} {
		for _, field := range []string{"open_critical_count", "open_critical_present", "open_high_count", "open_high_present",
			"open_medium_count", "open_low_count", "overdue_present", "overdue_critical_count", "overdue_high_count"} {
			pointers = append(pointers, "vuln-scanning:/scanners/"+scanner+"/"+field)
		}
	}
	return simulate.Same(v, note, pointers...)
}

func TestSimulatedMatrix(t *testing.T) {
	simHarness(t, simStanding).Matrix(t, simMatrixBase(t), simMatrixAxes(), simMatrixAlone, simMatrixTogether)
}

// simRules hold whatever the right values are, so they run on random
// rosters from the matrix's axes, and a broken one is a bug with no verdict
// to settle.
var simRules = []simulate.Rule{
	{
		Name: "reordering accounts, repositories, apps and credentials, and pages of two, change nothing",
		Change: func(r *roster.Roster, rng *rand.Rand) int {
			rng.Shuffle(len(r.Accounts), func(i, j int) { r.Accounts[i], r.Accounts[j] = r.Accounts[j], r.Accounts[i] })
			rng.Shuffle(len(r.Apps), func(i, j int) { r.Apps[i], r.Apps[j] = r.Apps[j], r.Apps[i] })
			repos, creds := r.VCS.Repositories, r.VCS.Credentials
			rng.Shuffle(len(repos), func(i, j int) { repos[i], repos[j] = repos[j], repos[i] })
			rng.Shuffle(len(creds), func(i, j int) { creds[i], creds[j] = creds[j], creds[i] })
			return 2
		},
		Check: func(before, after map[string]any) []string { return simulate.Unchanged(before, after, nil) },
	},
	{
		Name: "more members with two-factor never lowers its coverage",
		Change: func(r *roster.Roster, rng *rand.Rand) int {
			a := &r.Accounts[rng.IntN(len(r.Accounts))]
			a.Methods = append(slices.Clone(a.Methods), "two_factor")
			return 0
		},
		Check: func(before, after map[string]any) []string {
			return simulate.NeverLower(before, after, "access-posture:/members/local_mfa_member_count", "access-posture:/members/local_mfa_coverage_pct",
				"access-posture:/admins/local_mfa_admin_count", "access-posture:/admins/local_admin_mfa_coverage_pct")
		},
	},
	{
		Name: "an active ruleset requiring a pull request with an approval never lowers branch protection",
		Change: func(r *roster.Roster, rng *rand.Rand) int {
			repo := &r.VCS.Repositories[rng.IntN(len(r.VCS.Repositories))]
			repo.Protections = append(slices.Clone(repo.Protections), roster.BranchProtection{
				Key: "ruleset:rule-check", Enforcement: "active", Rules: []roster.BranchRule{{Type: "pull_request", Approvals: 1}},
			})
			return 0
		},
		Check: func(before, after map[string]any) []string {
			return simulate.NeverLower(before, after, "vcs-posture:/branch_protection/pr_required_repository_count", "vcs-posture:/branch_protection/pr_required_pct",
				"vcs-posture:/branch_protection/approving_reviews_repository_count", "vcs-posture:/branch_protection/approving_reviews_pct")
		},
	},
	{
		Name: "turning Dependabot alerts on never lowers their coverage",
		Change: func(r *roster.Roster, rng *rand.Rand) int {
			res := &r.Scanning.Resources[rng.IntN(len(r.Scanning.Resources))]
			res.Scans = maps2(res.Scans)
			res.Scans["Dependabot alerts"] = "enabled"
			return 0
		},
		Check: func(before, after map[string]any) []string {
			return simulate.NeverLower(before, after, "vcs-posture:/security_features/vuln_alerts_pct", "vuln-scanning:/scanners/1/coverage_pct",
				"vuln-scanning:/scanners/1/scanned_resource_count")
		},
	},
}

func TestSimulatedRules(t *testing.T) {
	simHarness(t, simMatrixStanding).Rules(t, simMatrixBase(t), simMatrixAxes(), simRules, 20, 20261112)
}

// simMatrixStanding is simStanding for the matrix, whose rules run on rows
// of every setting.
var simMatrixStanding = simStanding
