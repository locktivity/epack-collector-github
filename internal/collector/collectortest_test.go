package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

var kitOperations = []string{
	"github.installation_token.create",
	"github.orgs.get",
	"github.repositories.list",
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
	"github.org_invitations.list",
}

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/github.collector-result.json"

// kitSteps are an internal-level run's steps in order, with their titles.
// Runs below audit make only the first four.
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
				// each open alert count matches the findings rows.
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
				}, kitResultPath: kitStepPins()},
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
			{Name: "empty organization", Responses: kitEmptyTenantResponses()},
			{Name: "security settings read fails", Responses: kitSecurityOutageResponses()},
			{Name: "read-only token", Responses: kitReadOnlyResponses()},
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
		Ignore:      map[string][]string{DetailedPath: {"/diagnostics"}},
		Operations:  kitOperations,
		Insensitive: []string{"github.installation_token.create"},
	}
}

func TestCollectorKit(t *testing.T) {
	s := kitSuite()
	s.Scenarios = append(s.Scenarios, kitRecordings(t, "github-compliant", "github-noncompliant")...)
	collectortest.Run(t, s)
}

// TestCollectorKitTokenAuth checks the GITHUB_TOKEN path: the scenarios,
// call naming, and that a redirect never carries the token off GitHub. The
// fault matrix runs once, in the App suite, since both paths share every call
// after the sign-in.
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
			{Name: "clean", Responses: clean},
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
		Ignore:     map[string][]string{DetailedPath: {"/diagnostics"}},
		Operations: kitOperations[1:],
		SkipChecks: []string{"faults", "sensitivity", "levels"},
	})
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
	if gapAt(res, NormalizedPath, "/security_features/secret_scanning_pct") == nil {
		t.Error("the normalized secret scanning percentage should carry the same gap")
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
		kitOrgURL("/audit-log?phrase=created%3A%3E%3D2026-10-10&per_page=100"),
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
	if len(res.Result.Gaps) != 0 {
		t.Errorf("a clean run left gaps: %+v", res.Result.Gaps)
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
		{NormalizedPath, "/org_security/two_factor_required"},
		{DetailedPath, "/security_features/secret_scanning"},
		{DetailedPath, "/repositories/per_repo/0/rulesets/0/bypass_allowed"},
	} {
		gap := gapAt(res, at.path, at.pointer)
		if gap == nil || gap.Code != componentsdk.CodePermissionDenied {
			t.Errorf("gap at %s %s = %+v, want permission_denied", at.path, at.pointer, gap)
		}
	}
	if section, ok := emitted(t, res, NormalizedPath)["org_security"]; ok {
		t.Errorf("normalized org_security = %v, want two_factor_required left out rather than false", section)
	}
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
			out = append(out, sc)
		}
	}
	return out
}
