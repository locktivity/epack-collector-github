package collector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// fixtureRepo is one repository in a fixture-backed org. classic is the
// GraphQL branchProtectionRule node, nil for none. Its default-branch rules
// come from testdata/rulesets/rules_<name>.json unless rulesStatus is set.
type fixtureRepo struct {
	name        string
	classic     map[string]any
	rulesStatus int
}

// collectFixtureOrg runs a collection through the real GitHub client against
// a server that answers with the testdata/rulesets fixtures. Endpoints the
// fixtures don't cover return 404.
func collectFixtureOrg(t *testing.T, level componentsdk.Level, repos ...fixtureRepo) *OrgPosture {
	t.Helper()
	byName := map[string]fixtureRepo{}
	nodes := make([]map[string]any, 0, len(repos))
	for _, r := range repos {
		byName[r.name] = r
		nodes = append(nodes, map[string]any{
			"name":                          r.name,
			"owner":                         map[string]any{"login": "test-org"},
			"visibility":                    "PRIVATE",
			"defaultBranchRef":              map[string]any{"name": "main", "branchProtectionRule": r.classic},
			"hasVulnerabilityAlertsEnabled": true,
		})
	}
	noMorePages := map[string]any{"hasNextPage": false, "endCursor": ""}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		org := map[string]any{"repositories": map[string]any{"nodes": nodes, "pageInfo": noMorePages}}
		if strings.Contains(string(body), "membersWithRole") {
			org = map[string]any{"membersWithRole": map[string]any{"nodes": []any{}, "pageInfo": noMorePages}}
		}
		writeFixtureJSON(t, w, map[string]any{"data": map[string]any{"organization": org}})
	})
	mux.HandleFunc("GET /orgs/test-org", func(w http.ResponseWriter, r *http.Request) {
		writeFixtureJSON(t, w, map[string]any{"login": "test-org", "two_factor_requirement_enabled": true})
	})
	mux.HandleFunc("GET /repos/test-org/{repo}", func(w http.ResponseWriter, r *http.Request) {
		writeFixtureJSON(t, w, map[string]any{"name": r.PathValue("repo"), "security_and_analysis": map[string]any{}})
	})
	mux.HandleFunc("GET /repos/test-org/{repo}/rules/branches/main", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("rules per_page = %q, want 100", got)
		}
		repo := byName[r.PathValue("repo")]
		if repo.rulesStatus != 0 {
			w.WriteHeader(repo.rulesStatus)
			serveFixture(t, w, "forbidden.json")
			return
		}
		serveFixture(t, w, "rules_"+repo.name+".json")
	})
	mux.HandleFunc("GET /repos/test-org/{repo}/rulesets/{id}", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("includes_parents"); got != "true" {
			t.Errorf("ruleset includes_parents = %q, want true", got)
		}
		serveFixture(t, w, "ruleset_"+r.PathValue("id")+".json")
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := github.NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql")
	posture, err := NewWithClient(Config{Organization: "test-org"}, client).Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture
}

func serveFixture(t *testing.T, w http.ResponseWriter, name string) {
	body, err := os.ReadFile(filepath.Join("testdata", "rulesets", name))
	if err != nil {
		t.Errorf("missing fixture %s: %v", name, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write(body)
}

func writeFixtureJSON(t *testing.T, w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

// assertJSONEqual fails unless got marshals to the same JSON value as want.
func assertJSONEqual(t *testing.T, name string, got any, want string) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	var gotValue, wantValue any
	if err := json.Unmarshal(gotJSON, &gotValue); err != nil {
		t.Fatalf("%s: unmarshal: %v", name, err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("%s: expected value is not JSON: %v", name, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("%s =\n%s\nwant\n%s", name, gotJSON, want)
	}
}

func onlyRepoRow(t *testing.T, p *OrgPosture) RepoRow {
	t.Helper()
	if p.Repositories == nil || len(p.Repositories.PerRepo) != 1 {
		t.Fatalf("want one repository row, got %+v", p.Repositories)
	}
	return p.Repositories.PerRepo[0]
}

func TestRulesets_RepositoryRulesetOnly(t *testing.T) {
	p := collectFixtureOrg(t, componentsdk.LevelAudit, fixtureRepo{name: "repo-ruleset"})

	assertPct(t, "branch_protection_coverage", p.Posture.BranchProtectionCoverage, 100)
	assertJSONEqual(t, "branch_protection_rules", p.BranchProtectionRules, `{
		"pull_request_required": 100,
		"approving_reviews": 100,
		"dismiss_stale_reviews": 100,
		"code_owner_reviews": 0,
		"status_checks": 100,
		"signed_commits": 0,
		"admin_enforcement": null,
		"force_pushes_blocked": 100,
		"deletions_blocked": 100,
		"linear_history": 0,
		"repository_counts": {
			"pull_request_required": 1,
			"approving_reviews": 1,
			"dismiss_stale_reviews": 1,
			"code_owner_reviews": 0,
			"status_checks": 1,
			"signed_commits": 0,
			"admin_enforcement": null,
			"force_pushes_blocked": 1,
			"deletions_blocked": 1,
			"linear_history": 0
		}
	}`)

	row := onlyRepoRow(t, p)
	if row.BranchProtection != nil {
		t.Errorf("classic branch_protection = %+v, want none", row.BranchProtection)
	}
	assertJSONEqual(t, "effective_branch_protection", row.EffectiveBranchProtection, `{
		"protected": true,
		"pull_request_required": true,
		"approving_reviews": true,
		"required_approving_review_count": 1,
		"dismiss_stale_reviews": true,
		"code_owner_reviews": false,
		"status_checks": true,
		"signed_commits": false,
		"force_pushes_blocked": true,
		"deletions_blocked": true,
		"linear_history": false,
		"admin_enforcement": null,
		"supplied_by": {
			"pull_request_required": ["repository_ruleset"],
			"approving_reviews": ["repository_ruleset"],
			"required_approving_review_count": ["repository_ruleset"],
			"dismiss_stale_reviews": ["repository_ruleset"],
			"status_checks": ["repository_ruleset"],
			"force_pushes_blocked": ["repository_ruleset"],
			"deletions_blocked": ["repository_ruleset"]
		}
	}`)
	assertJSONEqual(t, "rulesets", row.Rulesets, `[{
		"id": 1001,
		"name": "Protect main",
		"source_type": "Repository",
		"source": "test-org/repo-ruleset",
		"enforcement": "active",
		"rules": ["deletion", "non_fast_forward", "pull_request", "required_status_checks"],
		"bypass_allowed": null
	}]`)
	assertJSONEqual(t, "default_branch_protected_count", p.Repositories.DefaultProtected, `1`)

	if p.Diagnostics == nil || len(p.Diagnostics.PermissionErrors) != 0 {
		t.Fatalf("diagnostics = %+v, want warnings only", p.Diagnostics)
	}
	if !anyContains(p.Diagnostics.Warnings, "bypass lists for 1 of 1 rulesets are not visible to this token") {
		t.Errorf("warnings = %v, want the hidden bypass list explained", p.Diagnostics.Warnings)
	}
	assertJSONEqual(t, "vcs-posture branch_protection", p.ToVCSPosture().BranchProtection, `{
		"pr_required_pct": 100,
		"approving_reviews_pct": 100,
		"status_checks_pct": 100,
		"signed_commits_pct": 0
	}`)
}

func TestRulesets_OrganizationRulesetOnly(t *testing.T) {
	p := collectFixtureOrg(t, componentsdk.LevelAudit, fixtureRepo{name: "org-ruleset"})

	assertPct(t, "branch_protection_coverage", p.Posture.BranchProtectionCoverage, 100)
	assertJSONEqual(t, "branch_protection_rules", p.BranchProtectionRules, `{
		"pull_request_required": 100,
		"approving_reviews": 100,
		"dismiss_stale_reviews": 0,
		"code_owner_reviews": 100,
		"status_checks": 0,
		"signed_commits": 100,
		"admin_enforcement": null,
		"force_pushes_blocked": 100,
		"deletions_blocked": 100,
		"linear_history": 0,
		"repository_counts": {
			"pull_request_required": 1,
			"approving_reviews": 1,
			"dismiss_stale_reviews": 0,
			"code_owner_reviews": 1,
			"status_checks": 0,
			"signed_commits": 1,
			"admin_enforcement": null,
			"force_pushes_blocked": 1,
			"deletions_blocked": 1,
			"linear_history": 0
		}
	}`)

	row := onlyRepoRow(t, p)
	assertJSONEqual(t, "effective_branch_protection", row.EffectiveBranchProtection, `{
		"protected": true,
		"pull_request_required": true,
		"approving_reviews": true,
		"required_approving_review_count": 2,
		"dismiss_stale_reviews": false,
		"code_owner_reviews": true,
		"status_checks": false,
		"signed_commits": true,
		"force_pushes_blocked": true,
		"deletions_blocked": true,
		"linear_history": false,
		"admin_enforcement": null,
		"supplied_by": {
			"pull_request_required": ["organization_ruleset"],
			"approving_reviews": ["organization_ruleset"],
			"required_approving_review_count": ["organization_ruleset"],
			"code_owner_reviews": ["organization_ruleset"],
			"signed_commits": ["organization_ruleset"],
			"force_pushes_blocked": ["organization_ruleset"],
			"deletions_blocked": ["organization_ruleset"]
		}
	}`)
	assertJSONEqual(t, "rulesets", row.Rulesets, `[{
		"id": 2001,
		"name": "Default branch baseline",
		"source_type": "Organization",
		"source": "test-org",
		"enforcement": "active",
		"rules": ["deletion", "non_fast_forward", "pull_request", "required_signatures"],
		"bypass_allowed": null
	}]`)
}

func TestRulesets_ClassicProtectionAndRulesets(t *testing.T) {
	p := collectFixtureOrg(t, componentsdk.LevelAudit, fixtureRepo{
		name: "both",
		classic: map[string]any{
			"requiresApprovingReviews":     true,
			"requiredApprovingReviewCount": 1,
			"dismissesStaleReviews":        true,
			"requiresStatusChecks":         true,
			"isAdminEnforced":              false,
			"allowsForcePushes":            false,
			"allowsDeletions":              false,
		},
	})

	assertPct(t, "branch_protection_coverage", p.Posture.BranchProtectionCoverage, 100)
	assertJSONEqual(t, "branch_protection_rules", p.BranchProtectionRules, `{
		"pull_request_required": 100,
		"approving_reviews": 100,
		"dismiss_stale_reviews": 100,
		"code_owner_reviews": 100,
		"status_checks": 100,
		"signed_commits": 100,
		"admin_enforcement": 0,
		"force_pushes_blocked": 100,
		"deletions_blocked": 100,
		"linear_history": 100,
		"repository_counts": {
			"pull_request_required": 1,
			"approving_reviews": 1,
			"dismiss_stale_reviews": 1,
			"code_owner_reviews": 1,
			"status_checks": 1,
			"signed_commits": 1,
			"admin_enforcement": 0,
			"force_pushes_blocked": 1,
			"deletions_blocked": 1,
			"linear_history": 1
		}
	}`)

	row := onlyRepoRow(t, p)
	if row.BranchProtection == nil || row.BranchProtection.RequiredApprovingReviewCount != 1 {
		t.Errorf("classic branch_protection = %+v, want the classic rule's detail", row.BranchProtection)
	}
	// Status checks come only from the classic rule, which exempts admins, so
	// admins are not held to every rule.
	assertJSONEqual(t, "effective_branch_protection", row.EffectiveBranchProtection, `{
		"protected": true,
		"pull_request_required": true,
		"approving_reviews": true,
		"required_approving_review_count": 2,
		"dismiss_stale_reviews": true,
		"code_owner_reviews": true,
		"status_checks": true,
		"signed_commits": true,
		"force_pushes_blocked": true,
		"deletions_blocked": true,
		"linear_history": true,
		"admin_enforcement": false,
		"supplied_by": {
			"pull_request_required": ["classic_branch_protection", "organization_ruleset"],
			"approving_reviews": ["classic_branch_protection", "organization_ruleset"],
			"required_approving_review_count": ["organization_ruleset"],
			"dismiss_stale_reviews": ["classic_branch_protection"],
			"code_owner_reviews": ["organization_ruleset"],
			"status_checks": ["classic_branch_protection"],
			"signed_commits": ["organization_ruleset"],
			"force_pushes_blocked": ["classic_branch_protection", "organization_ruleset"],
			"deletions_blocked": ["classic_branch_protection", "organization_ruleset"],
			"linear_history": ["repository_ruleset"]
		}
	}`)
	assertJSONEqual(t, "rulesets", row.Rulesets, `[
		{
			"id": 2001,
			"name": "Default branch baseline",
			"source_type": "Organization",
			"source": "test-org",
			"enforcement": "active",
			"rules": ["deletion", "non_fast_forward", "pull_request", "required_signatures"],
			"bypass_allowed": null
		},
		{
			"id": 1002,
			"name": "Linear history",
			"source_type": "Repository",
			"source": "test-org/both",
			"enforcement": "active",
			"rules": ["required_linear_history"],
			"bypass_allowed": null
		}
	]`)
}

func TestRulesets_EvaluateModeIsNotProtection(t *testing.T) {
	unprotected := `{
		"pull_request_required": 0,
		"approving_reviews": 0,
		"dismiss_stale_reviews": 0,
		"code_owner_reviews": 0,
		"status_checks": 0,
		"signed_commits": 0,
		"admin_enforcement": 0,
		"force_pushes_blocked": 0,
		"deletions_blocked": 0,
		"linear_history": 0,
		"repository_counts": {
			"pull_request_required": 0,
			"approving_reviews": 0,
			"dismiss_stale_reviews": 0,
			"code_owner_reviews": 0,
			"status_checks": 0,
			"signed_commits": 0,
			"admin_enforcement": 0,
			"force_pushes_blocked": 0,
			"deletions_blocked": 0,
			"linear_history": 0
		}
	}`

	t.Run("rules endpoint omits the ruleset", func(t *testing.T) {
		p := collectFixtureOrg(t, componentsdk.LevelAudit, fixtureRepo{name: "evaluate"})

		assertPct(t, "branch_protection_coverage", p.Posture.BranchProtectionCoverage, 0)
		assertJSONEqual(t, "branch_protection_rules", p.BranchProtectionRules, unprotected)
		row := onlyRepoRow(t, p)
		if row.EffectiveBranchProtection.Protected == nil || *row.EffectiveBranchProtection.Protected {
			t.Errorf("protected = %v, want false", row.EffectiveBranchProtection.Protected)
		}
		if row.Rulesets != nil {
			t.Errorf("rulesets = %+v, want none", row.Rulesets)
		}
	})

	// If the rules endpoint ever returned them, the ruleset's own enforcement
	// keeps them out.
	t.Run("ruleset details say evaluate", func(t *testing.T) {
		p := collectFixtureOrg(t, componentsdk.LevelAudit, fixtureRepo{name: "evaluate-returned"})

		assertPct(t, "branch_protection_coverage", p.Posture.BranchProtectionCoverage, 0)
		assertJSONEqual(t, "branch_protection_rules", p.BranchProtectionRules, unprotected)
		row := onlyRepoRow(t, p)
		if row.EffectiveBranchProtection.Protected == nil || *row.EffectiveBranchProtection.Protected {
			t.Errorf("protected = %v, want false", row.EffectiveBranchProtection.Protected)
		}
		if row.EffectiveBranchProtection.SuppliedBy != nil {
			t.Errorf("supplied_by = %v, want none", row.EffectiveBranchProtection.SuppliedBy)
		}
		assertJSONEqual(t, "rulesets", row.Rulesets, `[{
			"id": 3001,
			"name": "Review requirement trial",
			"source_type": "Organization",
			"source": "test-org",
			"enforcement": "evaluate",
			"rules": ["pull_request", "non_fast_forward"],
			"bypass_allowed": null
		}]`)
	})
}

func TestRulesets_ForbiddenRulesCallIsNullWithDiagnostic(t *testing.T) {
	t.Run("no classic protection", func(t *testing.T) {
		p := collectFixtureOrg(t, componentsdk.LevelAudit, fixtureRepo{name: "denied", rulesStatus: http.StatusForbidden})

		if p.Posture.BranchProtectionCoverage != nil {
			t.Errorf("branch_protection_coverage = %d, want null", *p.Posture.BranchProtectionCoverage)
		}
		assertJSONEqual(t, "branch_protection_rules", p.BranchProtectionRules, `{
			"pull_request_required": null,
			"approving_reviews": null,
			"dismiss_stale_reviews": null,
			"code_owner_reviews": null,
			"status_checks": null,
			"signed_commits": null,
			"admin_enforcement": null,
			"force_pushes_blocked": null,
			"deletions_blocked": null,
			"linear_history": null,
			"repository_counts": {
				"pull_request_required": null,
				"approving_reviews": null,
				"dismiss_stale_reviews": null,
				"code_owner_reviews": null,
				"status_checks": null,
				"signed_commits": null,
				"admin_enforcement": null,
				"force_pushes_blocked": null,
				"deletions_blocked": null,
				"linear_history": null
			}
		}`)
		row := onlyRepoRow(t, p)
		assertJSONEqual(t, "effective_branch_protection", row.EffectiveBranchProtection, `{
			"protected": null,
			"pull_request_required": null,
			"approving_reviews": null,
			"required_approving_review_count": null,
			"dismiss_stale_reviews": null,
			"code_owner_reviews": null,
			"status_checks": null,
			"signed_commits": null,
			"force_pushes_blocked": null,
			"deletions_blocked": null,
			"linear_history": null,
			"admin_enforcement": null
		}`)
		if p.Repositories.DefaultProtected != nil {
			t.Errorf("default_branch_protected_count = %d, want null", *p.Repositories.DefaultProtected)
		}
		if p.Diagnostics == nil || !anyContains(p.Diagnostics.PermissionErrors, "branch rulesets: got 403 on 1/1 repos when reading default-branch rules") {
			t.Fatalf("permission errors = %+v, want the 403 on the rules call", p.Diagnostics)
		}
		for _, msg := range p.Diagnostics.PermissionErrors {
			if strings.Contains(msg, "denied") {
				t.Errorf("diagnostic %q names the repository", msg)
			}
		}
		assertJSONEqual(t, "vcs-posture branch_protection", p.ToVCSPosture().BranchProtection, `{}`)
	})

	t.Run("classic protection still counts", func(t *testing.T) {
		p := collectFixtureOrg(t, componentsdk.LevelAudit, fixtureRepo{
			name:        "denied",
			rulesStatus: http.StatusForbidden,
			classic: map[string]any{
				"requiresApprovingReviews":     true,
				"requiredApprovingReviewCount": 1,
				"requiresStatusChecks":         true,
				"isAdminEnforced":              true,
			},
		})

		assertPct(t, "branch_protection_coverage", p.Posture.BranchProtectionCoverage, 100)
		assertJSONEqual(t, "branch_protection_rules", p.BranchProtectionRules, `{
			"pull_request_required": 100,
			"approving_reviews": 100,
			"dismiss_stale_reviews": null,
			"code_owner_reviews": null,
			"status_checks": 100,
			"signed_commits": null,
			"admin_enforcement": null,
			"force_pushes_blocked": 100,
			"deletions_blocked": 100,
			"linear_history": null,
			"repository_counts": {
				"pull_request_required": 1,
				"approving_reviews": 1,
				"dismiss_stale_reviews": null,
				"code_owner_reviews": null,
				"status_checks": 1,
				"signed_commits": null,
				"admin_enforcement": null,
				"force_pushes_blocked": 1,
				"deletions_blocked": 1,
				"linear_history": null
			}
		}`)
		row := onlyRepoRow(t, p)
		assertJSONEqual(t, "effective_branch_protection", row.EffectiveBranchProtection, `{
			"protected": true,
			"pull_request_required": true,
			"approving_reviews": true,
			"required_approving_review_count": null,
			"dismiss_stale_reviews": null,
			"code_owner_reviews": null,
			"status_checks": true,
			"signed_commits": null,
			"force_pushes_blocked": true,
			"deletions_blocked": true,
			"linear_history": null,
			"admin_enforcement": null,
			"supplied_by": {
				"pull_request_required": ["classic_branch_protection"],
				"approving_reviews": ["classic_branch_protection"],
				"required_approving_review_count": ["classic_branch_protection"],
				"status_checks": ["classic_branch_protection"],
				"force_pushes_blocked": ["classic_branch_protection"],
				"deletions_blocked": ["classic_branch_protection"]
			}
		}`)
	})
}

func TestRulesets_TrustLevelRollsUpAcrossRepositories(t *testing.T) {
	p := collectFixtureOrg(t, componentsdk.LevelTrust,
		fixtureRepo{name: "repo-ruleset"},
		fixtureRepo{name: "org-ruleset"},
		fixtureRepo{name: "evaluate"},
	)

	assertPct(t, "branch_protection_coverage", p.Posture.BranchProtectionCoverage, 66)
	assertPct(t, "pull_request_required", p.BranchProtectionRules.PullRequestRequired, 66)
	assertPct(t, "code_owner_reviews", p.BranchProtectionRules.CodeOwnerReviews, 33)
	if p.Repositories != nil {
		t.Error("trust must not emit repository rows")
	}
	artifact, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, name := range []string{"repo-ruleset", "org-ruleset", "Default branch baseline"} {
		if strings.Contains(string(artifact), name) {
			t.Errorf("trust artifact contains %q", name)
		}
	}
}

func TestRulesets_OneUnreadableRepositoryMakesOrgMetricsNull(t *testing.T) {
	p := collectFixtureOrg(t, componentsdk.LevelTrust,
		fixtureRepo{name: "repo-ruleset"},
		fixtureRepo{name: "denied", rulesStatus: http.StatusForbidden},
	)
	if p.Posture.BranchProtectionCoverage != nil || p.BranchProtectionRules.PullRequestRequired != nil {
		t.Errorf("coverage = %v, pull_request_required = %v, want null for both",
			p.Posture.BranchProtectionCoverage, p.BranchProtectionRules.PullRequestRequired)
	}
}
