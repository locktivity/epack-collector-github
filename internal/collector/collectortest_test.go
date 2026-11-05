package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

var kitOperations = []string{
	"github.installation_token.create",
	"github.orgs.get",
	"github.repositories.list",
	"github.installation_repositories.list",
	"github.branch_rules.list",
	"github.rulesets.get",
	"github.repos.get",
	"github.code_scanning_default_setup.get",
	"github.code_scanning_analyses.list",
	"github.org_settings.get",
	"github.secret_scanning_alerts.list",
	"github.code_scanning_alerts.list",
	"github.dependabot_alerts.list",
	"github.repo_contents.get",
	"github.org_hooks.list",
	"github.repo_hooks.list",
	"github.deploy_keys.list",
	"github.org_runners.list",
	"github.org_actions_secrets.list",
	"github.repo_runners.list",
	"github.environments.list",
	"github.environment_branch_policies.list",
	"github.environment_protection_rules.list",
	"github.audit_log.list",
	"github.org_installations.list",
	"github.org_personal_access_tokens.list",
	"github.org_members.list",
	"github.member_names.list",
	"github.org_admins.list",
	"github.outside_collaborators.list",
	"github.users.get",
	"github.org_members_2fa_disabled.list",
	"github.outside_collaborators_2fa_disabled.list",
	"github.org_invitations.list",
	"github.saml_identities.list",
}

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/github.collector-result.json"

// kitTokenResultPath is where the token suite's runs write their collector
// result, since the kit names it after the suite.
const kitTokenResultPath = "artifacts/github-token.collector-result.json"

// kitSteps are an internal-level run's steps in order, with their titles.
var kitSteps = [][2]string{
	{"sign_in", "Sign in"},
	{"repositories", "Repositories"},
	{"branch_rules", "Branch protection and rulesets"},
	{"security_settings", "Security settings"},
	{"org_settings", "Organization settings"},
	{"security_alerts", "Security alerts"},
	{"codeowners", "CODEOWNERS files"},
	{"webhooks", "Webhooks"},
	{"deploy_keys", "Deploy keys"},
	{"actions", "Actions runners and secrets"},
	{"environments", "Deployment environments"},
	{"audit_log", "Audit log"},
	{"apps", "Installed Apps"},
	{"tokens", "Fine-grained personal access tokens"},
	{"members", "Members and outside collaborators"},
	{"sso", "SAML single sign-on"},
}

// kitTrustSteps are a trust-level run's steps in order, when it collects
// every kind.
var kitTrustSteps = []string{
	"sign_in", "repositories", "branch_rules", "security_settings",
	"security_alerts", "deploy_keys", "apps", "tokens", "members", "sso",
}

// kitTrustStepPins pins a trust-level run's steps in order, and that there
// are no more.
func kitTrustStepPins() map[string]any {
	pins := map[string]any{}
	for i, name := range kitTrustSteps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = name
	}
	pins[fmt.Sprintf("/steps/%d", len(kitTrustSteps))] = collectortest.Absent
	return pins
}

// kitCleanAccess pins the clean run's access-posture values. alice and bob
// are members, carol an outside collaborator, and alice the one owner. bob
// has no two-factor authentication. Both members have a linked SAML
// identity. The organization has a fine-grained token that has never been
// used and expires, and two deploy keys, one of them read-write. The token
// has no creation date, so the rotation values are left out. Of the two
// installed Apps, renovate is suspended and does not count.
func kitCleanAccess() map[string]any {
	return map[string]any{
		"/system_type":                                 "code_host",
		"/sign_in/sso_configured":                      true,
		"/sign_in/mfa_required":                        true,
		"/sign_in/scim_enabled":                        true,
		"/sign_in/sso_required":                        collectortest.Absent,
		"/members/member_count":                        3,
		"/members/external_member_count":               1,
		"/members/sso_member_count":                    2,
		"/members/sso_coverage_pct":                    66,
		"/members/local_member_count":                  3,
		"/members/local_mfa_member_count":              2,
		"/members/local_mfa_coverage_pct":              66,
		"/members/inactive_pct":                        collectortest.Absent,
		"/admins/admin_count":                          1,
		"/admins/admin_share_pct":                      34,
		"/admins/local_mfa_admin_count":                1,
		"/admins/local_admin_mfa_coverage_pct":         100,
		"/root":                                        collectortest.Absent,
		"/credentials/credential_count":                3,
		"/credentials/never_expiring_credential_count": 2,
		"/credentials/never_expiring_pct":              67,
		"/credentials/unused_credential_count":         2,
		"/credentials/unused_pct":                      67,
		"/credentials/write_access_credential_count":   1,
		"/credentials/write_access_pct":                34,
		"/credentials/unrestricted_credential_count":   0,
		"/credentials/unrestricted_pct":                0,
		"/credentials/rotation_overdue_pct":            collectortest.Absent,
		"/connected_apps/app_count":                    1,
	}
}

// kitCleanVulns pins the clean run's vuln-scanning values. The Dependabot
// alerts are one low, one medium, and one high from March, and the code
// scanning alerts one critical from May and one with no security severity.
func kitCleanVulns() map[string]any {
	return map[string]any{
		"/scanners/0/scanner":                "dependabot",
		"/scanners/0/coverage_pct":           75,
		"/scanners/0/open_critical_present":  false,
		"/scanners/0/open_high_present":      true,
		"/scanners/0/overdue_present":        true,
		"/scanners/0/open_high_count":        1,
		"/scanners/0/open_medium_count":      1,
		"/scanners/0/open_low_count":         1,
		"/scanners/0/overdue_high_count":     1,
		"/scanners/1/scanner":                "code_scanning",
		"/scanners/1/coverage_pct":           50,
		"/scanners/1/open_critical_count":    1,
		"/scanners/1/open_medium_count":      0,
		"/scanners/1/overdue_critical_count": 1,
		"/scanners/2/scanner":                "secret_scanning",
		"/scanners/2/enabled":                true,
		"/scanners/2/coverage_pct":           50,
		"/scanners/2/open_critical_present":  collectortest.Absent,
		"/scanners/3":                        collectortest.Absent,
	}
}

// kitStepPins pins the steps in order, and that there are no more.
func kitStepPins() map[string]any {
	pins := map[string]any{}
	for i, s := range kitSteps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = s[0]
		pins[fmt.Sprintf("/steps/%d/title", i)] = s[1]
	}
	pins[fmt.Sprintf("/steps/%d", len(kitSteps))] = collectortest.Absent
	return pins
}

func kitConfig() map[string]any {
	return map[string]any{
		"organization":     kitOrg,
		"app_id":           kitAppID,
		"installation_id":  kitInstallationID,
		"exclude_patterns": []any{"sandbox-*"},
		"level":            "internal",
	}
}

func kitSecrets() map[string]string {
	return map[string]string{"GITHUB_APP_PRIVATE_KEY": kitPrivateKey()}
}

// kitNotEnabled is the meaning of a 404 from an alert endpoint.
const kitNotEnabled = "the feature is not enabled for the repository, so it has no alerts"

// kitSecurityOutageResponses reproduce the October 2026 incident: GitHub
// answering one repository's settings read with 502, which the collector
// used to read as every feature disabled.
func kitSecurityOutageResponses() []collectortest.Response {
	return replaceResponse(kitResponses(), collectortest.Response{
		URL:    kitRepoURL("org-ruleset", ""),
		Status: http.StatusBadGateway,
		Body:   `{"message":"Server Error"}`,
	})
}

func kitSuite() collectortest.Suite {
	return collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitConfig(),
		Secrets: kitSecrets(),
		Clock:   kitClock,
		Scenarios: []collectortest.Scenario{
			{
				Name:      "clean",
				Responses: kitResponses(),
				// The second page of each list proves it was followed, and
				// each open alert count matches the findings rows. The
				// archived count is the organization's, though no archived
				// repository is in scope, and token permissions keep their
				// access level.
				Expect: map[string]map[string]any{DetailedPath: {
					"/actions/org_runners/1/name":                               "runner-2",
					"/actions/org_secret_names/1":                               "NPM_TOKEN",
					"/actions/truncated":                                        collectortest.Absent,
					"/apps/per_installation/1/app_slug":                         "renovate",
					"/apps/truncated":                                           collectortest.Absent,
					"/security_features/per_repo/0/open_secret_scanning_alerts": 1,
					"/security_features/per_repo/0/open_code_scanning_alerts":   1,
					"/security_features/per_repo/0/open_dependabot_alerts":      2,
					"/security_features/findings/dependabot/1/package":          "lodash",
					"/security_features/per_repo/2/open_secret_scanning_alerts": 0,
					"/repositories/archived_count":                              1,
					"/tokens/per_token/0/permissions":                           []any{"contents:read", "members:read"},
					"/scope/repository_selection":                               "all",
					"/members/per_member/0/saml_name_id":                        "alice@idp.example.com",
					"/members/per_member/1/saml_name_id":                        "bob@idp.example.com",
					"/members/per_member/2/saml_name_id":                        collectortest.Absent,
					"/members/per_member/2/two_factor_enabled":                  true,
				}, AccessPath: kitCleanAccess(), VulnPath: kitCleanVulns(), kitResultPath: kitStepPins()},
			},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					Method: http.MethodPost,
					URL:    kitTokenResponse().URL,
					Status: http.StatusUnauthorized,
					Body:   `{"message":"A JSON web token could not be decoded","documentation_url":"https://docs.github.com/rest"}`,
				}},
			},
			{
				Name:      "empty organization",
				Responses: kitEmptyTenantResponses(),
				// Over no one and no repositories, each percentage is null
				// and each present flag false.
				Expect: map[string]map[string]any{
					AccessPath: {
						"/sign_in/sso_configured":              false,
						"/sign_in/mfa_required":                false,
						"/members/members_present":             false,
						"/members/local_mfa_coverage_pct":      nil,
						"/admins/local_admins_present":         false,
						"/admins/local_admin_mfa_coverage_pct": nil,
						"/credentials/credentials_present":     false,
						"/credentials/never_expiring_pct":      nil,
						"/connected_apps/apps_present":         false,
						"/members/inactive_pct":                collectortest.Absent,
						"/root":                                collectortest.Absent,
					},
					VulnPath: {
						"/scanners/0/resources_present":     false,
						"/scanners/0/coverage_pct":          nil,
						"/scanners/0/open_critical_present": false,
						"/scanners/1/overdue_present":       false,
					},
				},
			},
			{
				Name:      "trust level",
				Config:    map[string]any{"level": "trust"},
				Responses: kitResponses(),
				// A trust run writes the present flags and percentages the
				// prototype's cards read, and none of the counts.
				Expect: map[string]map[string]any{
					AccessPath: {
						"/sign_in/mfa_required":                true,
						"/members/members_present":             true,
						"/members/member_count":                collectortest.Absent,
						"/admins/local_admins_present":         true,
						"/admins/local_admin_mfa_coverage_pct": 100,
						"/admins/admin_count":                  collectortest.Absent,
						"/credentials/credentials_present":     true,
						"/credentials/never_expiring_pct":      67,
						"/credentials/credential_count":        collectortest.Absent,
					},
					VulnPath: {
						"/scanners/0/coverage_pct":          75,
						"/scanners/0/resource_count":        collectortest.Absent,
						"/scanners/0/open_critical_present": false,
						"/scanners/0/overdue_present":       true,
						"/scanners/1/open_critical_present": true,
						"/scanners/1/open_critical_count":   collectortest.Absent,
					},
					kitResultPath: kitTrustStepPins(),
				},
			},
			{
				Name:      "App without the members permission",
				Responses: kitNoMembersPermissionResponses(),
				// The member, owner, and SAML values are left out with
				// permission gaps, and the run goes on.
				Expect: map[string]map[string]any{
					AccessPath: {
						"/sign_in/mfa_required":                true,
						"/sign_in/sso_configured":              collectortest.Absent,
						"/members/members_present":             collectortest.Absent,
						"/admins/admins_present":               collectortest.Absent,
						"/admins/local_admin_mfa_coverage_pct": collectortest.Absent,
						"/credentials/credentials_present":     true,
					},
					DetailedPath: {"/members": collectortest.Absent},
				},
			},
			{
				Name:      "no SAML or two-factor requirement",
				Responses: kitNoRequirementsResponses(),
				// Without the requirement, bob and the outside collaborator
				// carol have no two-factor authentication. No member has a
				// SAML NameID.
				Expect: map[string]map[string]any{
					AccessPath: {
						"/sign_in/sso_configured":              false,
						"/sign_in/scim_enabled":                false,
						"/sign_in/mfa_required":                false,
						"/members/sso_member_count":            0,
						"/members/sso_coverage_pct":            0,
						"/members/local_mfa_member_count":      1,
						"/members/local_mfa_coverage_pct":      33,
						"/admins/local_admin_mfa_coverage_pct": 100,
					},
					DetailedPath: {
						"/members/per_member/0/saml_name_id":       collectortest.Absent,
						"/members/per_member/2/login":              "carol",
						"/members/per_member/2/two_factor_enabled": false,
					},
				},
			},
			{
				Name:      "no fine-grained tokens",
				Responses: replaceResponse(kitResponses(), collectortest.Response{URL: kitOrgURL("/personal-access-tokens?per_page=100"), Body: `[]`}),
				// The deploy keys all have a creation date, and the
				// read-write one was created in January.
				Expect: map[string]map[string]any{AccessPath: {
					"/credentials/credential_count":                  2,
					"/credentials/rotation_overdue_credential_count": 1,
					"/credentials/rotation_overdue_pct":              50,
					"/credentials/unrestricted_pct":                  0,
				}},
			},
			{
				Name:      "alert lists refused",
				Responses: kitAlertsRefusedResponses(),
				// repo-ruleset's code scanning and Dependabot alerts are
				// refused. The high Dependabot alert on classic-only still
				// shows, and the coverage comes from the settings.
				Expect: map[string]map[string]any{VulnPath: {
					"/scanners/0/open_high_present":     true,
					"/scanners/0/overdue_present":       true,
					"/scanners/0/open_critical_present": collectortest.Absent,
					"/scanners/0/open_high_count":       collectortest.Absent,
					"/scanners/1/open_critical_present": collectortest.Absent,
					"/scanners/1/overdue_present":       collectortest.Absent,
					"/scanners/1/coverage_pct":          50,
				}},
			},
			{Name: "security settings read fails", Responses: kitSecurityOutageResponses()},
			{Name: "read-only token", Responses: kitReadOnlyResponses()},
			{
				Name:      "lists at the cap",
				Responses: kitListsAtTheCapResponses(),
				// Each list may hold more than it read, so its counts are
				// null, which the schema's x-epack-null explains, and the
				// rows read are flagged.
				Expect: map[string]map[string]any{DetailedPath: {
					"/members/member_count":         nil,
					"/members/truncated":            true,
					"/webhooks/org_count":           nil,
					"/webhooks/repo_count":          1,
					"/webhooks/count_by_event":      collectortest.Absent,
					"/webhooks/truncated":           true,
					"/deploy_keys/total_count":      nil,
					"/deploy_keys/read_write_count": nil,
					"/deploy_keys/truncated":        true,
					"/tokens/grant_count":           nil,
					"/tokens/truncated":             true,
				}},
			},
			kitSelectedScenario(),
		},
		Required: []string{"github.installation_token.create", "github.orgs.get"},
		Semantics: []collectortest.Semantic{
			{Operation: "github.orgs.get", Fault: "404", Meaning: "organization not found", ExpectFailure: componentsdk.CodeConfigInvalid},
			{Operation: "github.code_scanning_default_setup.get", Fault: "404", Meaning: "default setup is not available for the repository, so the collector looks for code scanning analyses instead"},
			{Operation: "github.code_scanning_analyses.list", Fault: "404", Meaning: "the repository has no code scanning analyses"},
			{Operation: "github.secret_scanning_alerts.list", Fault: "404", Meaning: kitNotEnabled},
			{Operation: "github.code_scanning_alerts.list", Fault: "404", Meaning: kitNotEnabled},
			{Operation: "github.dependabot_alerts.list", Fault: "404", Meaning: kitNotEnabled},
			{Operation: "github.repo_contents.get", Fault: "404", Meaning: "no CODEOWNERS file at that path"},
			{Operation: "github.users.get", Fault: "404", Meaning: "the user was deleted or suspended, so it has no display name"},
			{Operation: "github.environments.list", Fault: "404", Meaning: "the repository has no deployment environments"},
			{Operation: "github.environment_branch_policies.list", Fault: "404", Meaning: "the environment has no custom deployment branch policies"},
			{Operation: "github.environment_protection_rules.list", Fault: "404", Meaning: "the environment has no custom deployment protection rules"},
			{
				Operation: "github.audit_log.list", Fault: "404", Meaning: "the organization does not have GitHub Enterprise Cloud",
				Expect: map[string]map[string]any{DetailedPath: {"/audit_log": nil}},
			},
			{
				Operation: "github.org_personal_access_tokens.list", Fault: "404", Meaning: "the organization has no fine-grained personal access token policy",
				Expect: map[string]map[string]any{DetailedPath: {"/tokens": nil}},
			},
		},
		Operations:  kitOperations,
		Insensitive: []string{"github.installation_token.create"},
	}
}

// kitSelectedDetail pins a run on every fixture repository but kitOutsider.
// GitHub lists kitOutsider, which is public, and nothing answers a call about
// it. The coverage is over GitHub's count of all six repositories.
func kitSelectedDetail() map[string]any {
	return map[string]any{
		"/scope/repository_selection":      "selected",
		"/scope/repository_count":          6,
		"/scope/included_repository_count": 3,
		"/scope/repositories_coverage":     50,
		"/repositories/archived_count":     1,
		"/repositories/per_repo/0/name":    kitOrg + "/repo-ruleset",
		"/repositories/per_repo/1/name":    kitOrg + "/classic-only",
		"/repositories/per_repo/2/name":    kitOrg + "/classic-and-org",
		"/repositories/per_repo/3":         collectortest.Absent,
	}
}

// kitSelectedScenario is a GitHub App installed on every fixture repository
// but kitOutsider.
func kitSelectedScenario() collectortest.Scenario {
	return collectortest.Scenario{
		Name:      "App on selected repositories",
		Responses: kitSelectedResponses(ptr(5)),
		Expect:    map[string]map[string]any{DetailedPath: kitSelectedDetail()},
	}
}

// TestCollectorKitSelectedRepositories runs the fault matrix on a GitHub App
// installed on selected repositories, the only kind of run that lists the
// installation's repositories, so the trace map can say what that list feeds.
func TestCollectorKitSelectedRepositories(t *testing.T) {
	s := kitSuite()
	// A suite named like the App suite would replace its scenarios under
	// COLLECTORTEST_OUT.
	s.Name = "github-selected"
	s.Scenarios = []collectortest.Scenario{kitSelectedScenario()}
	collectortest.Run(t, s)
}

func TestCollectorKit(t *testing.T) {
	s := kitSuite()
	s.Scenarios = append(s.Scenarios, kitRecordings(t, "github-compliant", "github-noncompliant")...)
	collectortest.Run(t, s)
}

// TestCollectorKitTokenAuth checks the GITHUB_TOKEN path: the scenarios,
// call naming, and that a redirect never carries the token off GitHub. Only an
// installation token calls the list of the installation's repositories, and
// that call from any other token matches no response. The fault matrix runs
// once, in the App suite, since both paths
// share every call after the sign-in.
func TestCollectorKitTokenAuth(t *testing.T) {
	config := kitConfig()
	delete(config, "app_id")
	delete(config, "installation_id")
	clean := kitResponses()[1:]
	collectortest.Run(t, collectortest.Suite{
		Spec: Spec("test", "collectortest"),
		Run:  Run,
		// The App suite writes its scenarios under COLLECTORTEST_OUT/github
		// for the evidence diff, and a suite with the same name would
		// replace them.
		Name:    "github-token",
		Config:  config,
		Secrets: map[string]string{"GITHUB_TOKEN": "ghp_kittoken0123456789abcdef"},
		Clock:   kitClock,
		Scenarios: []collectortest.Scenario{
			{
				Name:      "clean",
				Responses: clean,
				Expect: map[string]map[string]any{
					DetailedPath: {
						"/scope/repository_selection": nil,
						"/scope/repository_count":     len(kitRepos),
					},
					kitTokenResultPath: {"/signed_in_as/kind": github.CredentialToken},
				},
			},
			{
				Name:      "installation token on selected repositories",
				Secrets:   map[string]string{"GITHUB_TOKEN": kitToken},
				Responses: kitSelectedResponses(ptr(5))[1:],
				Expect: map[string]map[string]any{
					DetailedPath: kitSelectedDetail(),
					kitTokenResultPath: {
						"/signed_in_as/kind":        github.CredentialInstallationToken,
						"/signed_in_as/auth_method": componentsdk.AuthAPIToken,
					},
				},
			},
			{
				Name:      "installation token on all repositories",
				Secrets:   map[string]string{"GITHUB_TOKEN": kitToken},
				Responses: kitInstallationTokenOnAllResponses(),
				Expect: map[string]map[string]any{DetailedPath: {
					"/scope/repository_selection":   "all",
					"/scope/repository_count":       len(kitRepos),
					"/repositories/per_repo/1/name": kitOrg + "/" + kitOutsider,
				}},
			},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses:     []collectortest.Response{{URL: kitOrgURL(""), Status: http.StatusUnauthorized, Body: `{"message":"Bad credentials"}`}},
			},
			{
				Name:          "organization not found",
				ExpectFailure: componentsdk.CodeConfigInvalid,
				Responses:     []collectortest.Response{kitNotFoundResponse(kitOrgURL(""))},
			},
		},
		Required:   []string{"github.orgs.get"},
		Operations: kitTokenOperations(),
		SkipChecks: []string{"faults", "sensitivity", "levels"},
	})
}

// kitTokenOperations are the operations a token run can call: all but the
// App's token exchange.
func kitTokenOperations() []string {
	var ops []string
	for _, op := range kitOperations {
		if op != "github.installation_token.create" {
			ops = append(ops, op)
		}
	}
	return ops
}

func runKit(t *testing.T, config map[string]any, secrets map[string]string, responses []collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	return componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   secrets,
		Transport: replay,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Clock:     func() time.Time { return kitClock },
	})
}

func gapAt(res componentsdk.InProcessResult, path, pointer string) *componentsdk.Gap {
	if res.Result == nil {
		return nil
	}
	for i, g := range res.Result.Gaps {
		if g.Path == path && g.Pointer == pointer {
			return &res.Result.Gaps[i]
		}
	}
	return nil
}

func emitted(t *testing.T, res componentsdk.InProcessResult, path string) map[string]any {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Path == path {
			var doc map[string]any
			if err := json.Unmarshal(a.Data, &doc); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			return doc
		}
	}
	t.Fatalf("artifact %s was not emitted", path)
	return nil
}

func TestSecuritySettingsFailureLeavesFeaturesOutWithGaps(t *testing.T) {
	res := runKit(t, kitConfig(), kitSecrets(), kitSecurityOutageResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	features := emitted(t, res, DetailedPath)["security_features"].(map[string]any)
	for _, field := range []string{"code_scanning", "secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates"} {
		if features[field] != nil {
			t.Errorf("security_features.%s = %v, want null rather than a value that counts the unread repository as disabled", field, features[field])
		}
		gap := gapAt(res, DetailedPath, "/security_features/"+field)
		if gap == nil || gap.Status != componentsdk.GapPartial || gap.Code != componentsdk.CodeVendorError || gap.Unmeasured != 1 {
			t.Errorf("gap for %s = %+v, want partial vendor_error with 1 unmeasured", field, gap)
		}
	}
	if features["vulnerability_alerts"] == nil {
		t.Error("vulnerability_alerts comes from the repository list and should survive the settings failure")
	}
	if gapAt(res, VulnPath, "/scanners/2/coverage_pct") == nil {
		t.Error("the secret scanning coverage in vuln-scanning should carry the same gap")
	}
	if res.Result.Outcome.Status != componentsdk.OutcomePartial {
		t.Errorf("outcome = %+v, want partial", res.Result.Outcome)
	}
	for _, op := range res.Result.Calls.Operations {
		if op.Name == "github.repos.get" && op.Retries == 0 {
			t.Error("the SDK should retry the failed settings read")
		}
	}
}

func TestRejectedTokenFailsTheRun(t *testing.T) {
	config := kitConfig()
	delete(config, "app_id")
	res := runKit(t, config, map[string]string{"GITHUB_TOKEN": "ghp_kittoken0123456789abcdef"}, []collectortest.Response{
		{URL: kitOrgURL(""), Status: http.StatusUnauthorized, Body: `{"message":"Bad credentials"}`},
	})
	if res.ExitCode != 3 || res.Failure == nil || res.Failure.Code != componentsdk.CodeAuthFailed {
		t.Fatalf("exit %d, failure %+v; want exit 3 with auth_failed", res.ExitCode, res.Failure)
	}
	if len(res.Artifacts) != 0 {
		t.Errorf("a rejected credential emitted %d artifacts", len(res.Artifacts))
	}
}

// A 404 that shows the organization lacks a feature leaves the surface out
// as not_licensed, and the gap still names the call GitHub answered.
func TestNotLicensedGapsNameTheirCall(t *testing.T) {
	responses := kitResponses()
	for _, url := range []string{
		kitAuditLogURL(),
		kitOrgURL("/personal-access-tokens?per_page=100"),
	} {
		responses = replaceResponse(responses, kitNotFoundResponse(url))
	}
	res := runKit(t, kitConfig(), kitSecrets(), responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for pointer, operation := range map[string]string{
		"/audit_log": "github.audit_log.list",
		"/tokens":    "github.org_personal_access_tokens.list",
	} {
		g := gapAt(res, DetailedPath, pointer)
		switch {
		case g == nil:
			t.Errorf("%s: no gap", pointer)
		case g.Code != componentsdk.CodeNotLicensed || g.Operation != operation || g.Call == 0:
			t.Errorf("%s: code %s, operation %q, call %d; want not_licensed naming a %s call", pointer, g.Code, g.Operation, g.Call, operation)
		}
	}
}

// A repository sent out of the organization has the audit log actions
// repo.transfer_start and repo.transfer_outgoing. They count in the repo
// category along with repo.transfer.
// The collector result holds the sso_required detail as the collector wrote
// it, with nothing scrubbed.
func TestSSORequiredGapDetailIsNotScrubbed(t *testing.T) {
	res := runKit(t, kitConfig(), kitSecrets(), kitResponses())
	g := gapAt(res, AccessPath, "/sign_in/sso_required")
	if g == nil || g.Detail != ssoRequiredNotRead {
		t.Errorf("sso_required gap = %+v, want the detail %q", g, ssoRequiredNotRead)
	}
}

func TestRepositoryTransfersCountInTheAuditLog(t *testing.T) {
	for _, action := range []string{"repo.transfer", "repo.transfer_start", "repo.transfer_outgoing"} {
		t.Run(action, func(t *testing.T) {
			event := map[string]any{"action": action, "actor": "alice", "repo": kitOrg + "/repo-ruleset", "created_at": 1760000000000}
			responses := replaceResponse(kitResponses(), collectortest.Response{URL: kitAuditLogURL(), Body: kitJSON([]any{event})})
			res := runKit(t, kitConfig(), kitSecrets(), responses)
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			log, _ := emitted(t, res, DetailedPath)["audit_log"].(map[string]any)
			byCategory, _ := log["count_by_category"].(map[string]any)
			events, _ := log["events"].([]any)
			if byCategory["repo"] != float64(1) || len(events) != 1 {
				t.Errorf("repo count %v with %d events, want 1 and 1", byCategory["repo"], len(events))
			}
		})
	}
}

func TestRunRecordsTheSignedInApp(t *testing.T) {
	res := runKit(t, kitConfig(), kitSecrets(), kitResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	got := res.Result.SignedInAs
	if got == nil || got.Provider != "github" || got.Kind != "app_installation" || got.TenantID != kitOrg || got.ID != "123456" {
		t.Fatalf("signed_in_as = %+v", got)
	}
	if strings.Join(got.Scopes, ",") != "administration:read,contents:read,members:read,metadata:read" {
		t.Errorf("scopes = %v, want the installation's permissions", got.Scopes)
	}
	if got.AuthMethod != componentsdk.AuthPrivateKeyJWT || !got.ReadOnly {
		t.Errorf("auth method %q, read-only %t; want %q and read-only, since every permission is read", got.AuthMethod, got.ReadOnly, componentsdk.AuthPrivateKeyJWT)
	}
	// The only gaps are on values GitHub does not report or the collector
	// does not read.
	for _, g := range res.Result.Gaps {
		if g.Code != componentsdk.CodeUnsupported && g.Code != componentsdk.CodeNotRead {
			t.Errorf("a clean run left a %s gap at %s %s", g.Code, g.Path, g.Pointer)
		}
	}
}

// Each operation in the result names the permission its call needs. A
// denied call's gap names it as missing only for a GitHub App without it,
// since a token's permissions cannot be read.
func TestOperationsNameTheirPermission(t *testing.T) {
	refused := collectortest.Response{URL: kitOrgURL("/hooks?per_page=100"), Status: http.StatusForbidden, Body: kitIntegrationDenied}
	app := runKit(t, kitConfig(), kitSecrets(), replaceResponse(kitResponses(), refused))
	token := runKit(t, kitTokenConfig(), map[string]string{"GITHUB_TOKEN": "ghp_kittoken0123456789abcdef"}, replaceResponse(kitResponses()[1:], refused))
	for name, res := range map[string]componentsdk.InProcessResult{"app": app, "token": token} {
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("%s: run failed with exit %d: %s", name, res.ExitCode, res.Stderr)
		}
		declared := map[string]string{}
		for _, op := range res.Operations {
			declared[op.Name] = op.Permission
		}
		if declared["github.org_members.list"] != "members:read" || declared["github.org_hooks.list"] != "organization_hooks:read" || declared["github.orgs.get"] != "" {
			t.Errorf("%s: permissions = %v, want members:read, organization_hooks:read, and none for the sign-in", name, declared)
		}
	}
	for name, tc := range map[string]struct {
		res  componentsdk.InProcessResult
		want string
	}{"app": {app, "organization_hooks:read"}, "token": {token, ""}} {
		var found bool
		for _, g := range tc.res.Result.Gaps {
			if g.Operation != "github.org_hooks.list" {
				continue
			}
			found = true
			if g.Code != componentsdk.CodePermissionDenied || g.MissingPermission != tc.want {
				t.Errorf("%s: gap at %s is %s with missing permission %q, want permission_denied with %q", name, g.Pointer, g.Code, g.MissingPermission, tc.want)
			}
		}
		if !found {
			t.Errorf("%s: no gap from github.org_hooks.list", name)
		}
	}
}

func TestRunRecordsTheSignedInToken(t *testing.T) {
	config := kitConfig()
	delete(config, "app_id")
	delete(config, "installation_id")
	res := runKit(t, config, map[string]string{"GITHUB_TOKEN": "ghp_kittoken0123456789abcdef"}, kitResponses()[1:])
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	got := res.Result.SignedInAs
	if got == nil || got.Kind != "token" || got.AuthMethod != componentsdk.AuthAPIToken || got.ReadOnly {
		t.Fatalf("signed_in_as = %+v, want a token, signed in with %q and not shown read-only", got, componentsdk.AuthAPIToken)
	}
}

func TestTokenRefreshesCountAsTheExchange(t *testing.T) {
	// An expired token makes ghinstallation refresh it before every call,
	// with that call's context.
	token := kitTokenResponse()
	token.Body = strings.Replace(token.Body, "2099-01-01T00:00:00Z", "2020-01-01T00:00:00Z", 1)
	res := runKit(t, kitConfig(), kitSecrets(), replaceResponse(kitResponses(), token))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	exchanges := 0
	for _, op := range res.Result.Calls.Operations {
		if op.Name == "github.installation_token.create" {
			exchanges = op.Calls
			continue
		}
		if n := op.Statuses["201"]; n > 0 {
			t.Errorf("%s counted %d token exchanges as its own calls", op.Name, n)
		}
	}
	if exchanges < 2 {
		t.Errorf("github.installation_token.create counted %d calls, want the sign-in and each refresh", exchanges)
	}
}

func TestRequestRowsCarryNoNames(t *testing.T) {
	res := runKit(t, kitConfig(), kitSecrets(), kitResponses())
	if res.ExitCode != 0 || res.Result == nil || len(res.Result.Calls.Requests) == 0 {
		t.Fatalf("run failed with exit %d or recorded no requests: %s", res.ExitCode, res.Stderr)
	}
	names := append([]string{kitOrg, "carol", "production", "staging", "CODEOWNERS", "main"}, kitRepos...)
	for _, row := range res.Result.Calls.Requests {
		for _, segment := range strings.Split(row.Route, "/") {
			for _, name := range names {
				if segment == name {
					t.Errorf("%s route %s names %q", row.Operation, row.Route, name)
				}
			}
		}
	}
}

func TestHiddenSettingsAreLeftOutAsPermissionGaps(t *testing.T) {
	res := runKit(t, kitConfig(), kitSecrets(), kitReadOnlyResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, at := range []struct{ path, pointer string }{
		{DetailedPath, "/access_control/two_factor_required"},
		{AccessPath, "/sign_in/mfa_required"},
		{DetailedPath, "/security_features/secret_scanning"},
		{DetailedPath, "/repositories/per_repo/0/rulesets/0/bypass_allowed"},
	} {
		gap := gapAt(res, at.path, at.pointer)
		if gap == nil || gap.Code != componentsdk.CodePermissionDenied {
			t.Errorf("gap at %s %s = %+v, want permission_denied", at.path, at.pointer, gap)
		}
	}
	signIn, _ := emitted(t, res, AccessPath)["sign_in"].(map[string]any)
	if v, ok := signIn["mfa_required"]; ok {
		t.Errorf("access-posture mfa_required = %v, want it left out rather than false", v)
	}
}

func kitScope(t *testing.T, res componentsdk.InProcessResult) map[string]any {
	t.Helper()
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	scope, _ := emitted(t, res, DetailedPath)["scope"].(map[string]any)
	return scope
}

func TestSelectedInstallationNeedsTheOrganizationCount(t *testing.T) {
	res := runKit(t, kitConfig(), kitSecrets(), kitSelectedResponses(nil))
	scope := kitScope(t, res)
	if scope["included_repository_count"] != float64(3) {
		t.Errorf("included_repository_count = %v, want 3", scope["included_repository_count"])
	}
	for _, field := range []string{"repository_count", "repositories_coverage"} {
		if scope[field] != nil {
			t.Errorf("%s = %v, want it left out", field, scope[field])
		}
		gap := gapAt(res, DetailedPath, "/scope/"+field)
		if gap == nil || gap.Code != componentsdk.CodePermissionDenied || gap.MissingPermission != "organization_administration:read" {
			t.Errorf("gap at /scope/%s = %+v, want permission_denied naming organization_administration:read", field, gap)
		}
	}
}

func TestSelectedInstallationLeavesOutACountBelowItsList(t *testing.T) {
	res := runKit(t, kitConfig(), kitSecrets(), kitSelectedResponses(ptr(2)))
	scope := kitScope(t, res)
	for _, field := range []string{"repository_count", "repositories_coverage"} {
		if scope[field] != nil {
			t.Errorf("%s = %v, want it left out", field, scope[field])
		}
		if gap := gapAt(res, DetailedPath, "/scope/"+field); gap == nil || gap.Code != componentsdk.CodeInvalidResponse {
			t.Errorf("gap at /scope/%s = %+v, want invalid_response", field, gap)
		}
	}
}

func TestFailedInstallationListLeavesTheRepositoryValuesOut(t *testing.T) {
	responses := replaceResponse(kitSelectedResponses(ptr(5)), collectortest.Response{
		URL:    kitInstallationReposURL,
		Status: http.StatusBadGateway,
		Body:   `{"message":"Server Error"}`,
	})
	res := runKit(t, kitConfig(), kitSecrets(), responses)
	scope := kitScope(t, res)
	if scope["repository_selection"] != "selected" {
		t.Errorf("repository_selection = %v, want selected, as the token exchange said", scope["repository_selection"])
	}
	for _, pointer := range []string{"/scope/repository_count", "/scope/included_repository_count", "/posture/branch_protection_coverage"} {
		if gap := gapAt(res, DetailedPath, pointer); gap == nil || gap.Operation != "github.installation_repositories.list" {
			t.Errorf("gap at %s = %+v, want one naming github.installation_repositories.list", pointer, gap)
		}
	}
}

func TestTokenExchangeWithoutASelectionAsksTheInstallation(t *testing.T) {
	responses := replaceResponse(kitResponses(), kitTokenResponseFor(""))
	responses = append(responses, kitInstallationOnAllResponse())
	scope := kitScope(t, runKit(t, kitConfig(), kitSecrets(), responses))
	if scope["repository_selection"] != "all" || scope["repository_count"] != float64(len(kitRepos)) {
		t.Errorf("scope = %v, want all of the %d listed repositories", scope, len(kitRepos))
	}
}

// kitTokenConfig is the configuration of a run that signs in with GITHUB_TOKEN.
func kitTokenConfig() map[string]any {
	config := kitConfig()
	delete(config, "app_id")
	delete(config, "installation_id")
	return config
}

func TestInstallationTokenFailedListLeavesTheRepositoryValuesOut(t *testing.T) {
	responses := replaceResponse(kitSelectedResponses(ptr(5))[1:], collectortest.Response{
		URL:    kitInstallationReposURL,
		Status: http.StatusBadGateway,
		Body:   `{"message":"Server Error"}`,
	})
	res := runKit(t, kitTokenConfig(), map[string]string{"GITHUB_TOKEN": kitToken}, responses)
	scope := kitScope(t, res)
	if scope["repository_selection"] != nil {
		t.Errorf("repository_selection = %v, want it left out, since no exchange reported it", scope["repository_selection"])
	}
	for _, pointer := range []string{"/scope/repository_selection", "/scope/repository_count", "/scope/included_repository_count", "/posture/branch_protection_coverage"} {
		if gap := gapAt(res, DetailedPath, pointer); gap == nil || gap.Operation != "github.installation_repositories.list" {
			t.Errorf("gap at %s = %+v, want one naming github.installation_repositories.list", pointer, gap)
		}
	}
}

func TestInstallationTokenNeedsTheOrganizationCount(t *testing.T) {
	res := runKit(t, kitTokenConfig(), map[string]string{"GITHUB_TOKEN": kitToken}, kitSelectedResponses(nil)[1:])
	scope := kitScope(t, res)
	if scope["included_repository_count"] != float64(3) {
		t.Errorf("included_repository_count = %v, want 3", scope["included_repository_count"])
	}
	gap := gapAt(res, DetailedPath, "/scope/repositories_coverage")
	if gap == nil || gap.Code != componentsdk.CodePermissionDenied {
		t.Fatalf("gap at /scope/repositories_coverage = %+v, want permission_denied", gap)
	}
	if gap.MissingPermission != "" {
		t.Errorf("missing_permission = %q, want none, since the token's permissions cannot be read", gap.MissingPermission)
	}
}

// kitRecordingKinds are the kinds of evidence each recording's calls
// answer. The recordings were made before the collector wrote access-posture
// and vuln-scanning, so each run collects only the kinds its recorded calls
// cover. Recording again adds the calls the other kinds make.
var kitRecordingKinds = map[string][]any{
	"github-compliant":    {"vcs-posture"},
	"github-noncompliant": {"vcs-posture", "vuln-scanning", "details"},
}

// kitRecordingAnswers answer the calls a recording lacks because it was made
// before the collector made them. github-noncompliant was recorded before
// the detailed artifact took the members' SAML identities. Its organization
// has no GitHub Enterprise Cloud, as its 404 from the audit log shows, so it
// has no SAML identity provider. Recording again replaces these.
var kitRecordingAnswers = map[string][]collectortest.Response{
	"github-noncompliant": {kitNoSAMLResponse()},
}

// kitRecordings loads the scenarios TestRecord in record_test.go records
// from sandboxes, and logs each one not recorded yet.
func kitRecordings(t *testing.T, names ...string) []collectortest.Scenario {
	t.Helper()
	var out []collectortest.Scenario
	for _, name := range names {
		path := filepath.Join("testdata", "recordings", name+".json")
		sc, err := collectortest.LoadScenario(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("no recording at %s yet", path)
		case err != nil:
			t.Fatal(err)
		default:
			if kinds, ok := kitRecordingKinds[name]; ok {
				sc.Config = maps.Clone(sc.Config)
				sc.Config["collect"] = kinds
			}
			sc.Responses = append(sc.Responses, kitRecordingAnswers[name]...)
			out = append(out, sc)
		}
	}
	return out
}

func TestSecondaryRateLimitIsNoPermissionGap(t *testing.T) {
	// A 403 over a secondary rate limit can have Retry-After, or no rate limit
	// headers at all. Each value it leaves out has a rate_limited gap with no
	// permission to grant.
	const body = `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`
	for name, header := range map[string]http.Header{
		"with Retry-After":           {"Retry-After": []string{"60"}},
		"without rate limit headers": nil,
	} {
		t.Run(name, func(t *testing.T) {
			responses := kitResponses()
			for _, url := range []string{
				kitAlertListURL("classic-and-org", "dependabot"),
				kitRepoURL("org-ruleset", ""),
				kitRepoURL("repo-ruleset", "/actions/runners?per_page=100"),
			} {
				responses = replaceResponse(responses, collectortest.Response{URL: url, Status: http.StatusForbidden, Header: header, Body: body})
			}
			res := runKit(t, kitConfig(), kitSecrets(), responses)
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			for _, pointer := range []string{
				"/security_features/per_repo/3/open_dependabot_alerts",
				"/security_features/per_repo/1/secret_scanning",
				"/security_features/code_scanning",
				"/actions/repo_runner_count",
			} {
				g := gapAt(res, DetailedPath, pointer)
				if g == nil || g.Code != componentsdk.CodeRateLimited || g.Fix != "" || g.Warning != "" || g.MissingPermission != "" {
					t.Errorf("gap at %s = %+v, want rate_limited with no permission to grant", pointer, g)
				}
			}
			// The call is retried, and its row records no permission_denied.
			for _, op := range res.Operations {
				if op.Name == "github.dependabot_alerts.list" && (!op.Retried || op.Errors[componentsdk.CodePermissionDenied] > 0) {
					t.Errorf("%s: retried %t, errors %v; want retries and no permission_denied", op.Name, op.Retried, op.Errors)
				}
			}
			// With no Retry-After, each retry waits the minute GitHub asks for.
			for _, row := range res.Result.Calls.Requests {
				if row.Operation != "github.dependabot_alerts.list" || row.Attempt < 2 {
					continue
				}
				if header == nil && row.WaitedMS < time.Minute.Milliseconds() {
					t.Errorf("attempt %d of call %d waited %dms, want at least a minute", row.Attempt, row.Call, row.WaitedMS)
				}
			}
		})
	}
}
