package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// branchRulesJSON mirrors the Get-rules-for-a-branch payload: rules from an
// organization ruleset and a repository ruleset, each tagged with its source.
const branchRulesJSON = `[
	{"type": "deletion", "ruleset_source_type": "Organization", "ruleset_source": "owner", "ruleset_id": 20},
	{
		"type": "pull_request",
		"parameters": {
			"allowed_merge_methods": ["squash"],
			"dismiss_stale_reviews_on_push": true,
			"require_code_owner_review": true,
			"require_last_push_approval": false,
			"required_approving_review_count": 2,
			"required_review_thread_resolution": false
		},
		"ruleset_source_type": "Organization",
		"ruleset_source": "owner",
		"ruleset_id": 20
	},
	{
		"type": "required_status_checks",
		"parameters": {
			"strict_required_status_checks_policy": false,
			"required_status_checks": [{"context": "ci/test"}]
		},
		"ruleset_source_type": "Repository",
		"ruleset_source": "owner/repo",
		"ruleset_id": 10
	}
]`

func TestGetBranchRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/rules/branches/main" || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("unexpected request: %s", r.URL)
		}
		_, _ = fmt.Fprint(w, branchRulesJSON)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	rules, err := client.GetBranchRules(context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("rules = %+v, want 3", rules)
	}

	deletion := rules[0]
	if deletion.Type != RuleTypeDeletion || deletion.RulesetSourceType != "Organization" ||
		deletion.RulesetSource != "owner" || deletion.RulesetID != 20 || deletion.PullRequest != nil {
		t.Errorf("deletion rule parse wrong: %+v", deletion)
	}
	pr := rules[1]
	if pr.PullRequest == nil || pr.PullRequest.RequiredApprovingReviewCount != 2 ||
		!pr.PullRequest.DismissStaleReviewsOnPush || !pr.PullRequest.RequireCodeOwnerReview {
		t.Errorf("pull_request rule parse wrong: %+v", pr.PullRequest)
	}
	if checks := rules[2]; checks.Type != RuleTypeRequiredStatusChecks || checks.RulesetSourceType != "Repository" || checks.RulesetID != 10 {
		t.Errorf("required_status_checks rule parse wrong: %+v", checks)
	}
}

// setNextPage points the response's Link header at page 2 of the same rules.
func setNextPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Link", fmt.Sprintf(`<http://%s/repos/owner/repo/rules/branches/main?per_page=100&page=2>; rel="next"`, r.Host))
}

func TestGetBranchRules_FollowsPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = fmt.Fprint(w, `[{"type": "required_signatures", "ruleset_source_type": "Repository", "ruleset_source": "owner/repo", "ruleset_id": 10}]`)
			return
		}
		setNextPage(w, r)
		_, _ = fmt.Fprint(w, branchRulesJSON)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	rules, err := client.GetBranchRules(context.Background(), "owner", "repo", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 4 || rules[3].Type != RuleTypeRequiredSignatures {
		t.Errorf("rules = %+v, want both pages", rules)
	}
}

func TestGetBranchRules_FailureReturnsNoRules(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantDenied bool
	}{
		{
			name: "403",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, `{"message": "Resource not accessible by integration"}`)
			},
			wantDenied: true,
		},
		{
			name: "later page fails",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") == "2" {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				setNextPage(w, r)
				_, _ = fmt.Fprint(w, branchRulesJSON)
			},
		},
		{
			name: "malformed pull_request parameters",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, `[{"type": "pull_request", "parameters": {"required_approving_review_count": "two"}, "ruleset_id": 20}]`)
			},
		},
		{
			name: "body is not a rule list",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, `{"message": "unexpected"}`)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := NewClientWithHTTP(server.Client(), server.URL)
			rules, err := client.GetBranchRules(context.Background(), "owner", "repo", "main")
			if err == nil {
				t.Fatalf("rules = %+v, want an error", rules)
			}
			if rules != nil {
				t.Errorf("rules = %+v, want none alongside the error", rules)
			}
			if got := errors.Is(err, ErrPermissionDenied); got != tt.wantDenied {
				t.Errorf("errors.Is(err, ErrPermissionDenied) = %v, want %v (err: %v)", got, tt.wantDenied, err)
			}
		})
	}
}

func TestGetBranchRules_EscapesBranchName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.EscapedPath(), "/repos/owner/repo/rules/branches/release/v1%231"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	if _, err := client.GetBranchRules(context.Background(), "owner", "repo", "release/v1#1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetRepoRuleset(t *testing.T) {
	const ruleset = `{
		"id": 20,
		"name": "Default branch baseline",
		"target": "branch",
		"source_type": "Organization",
		"source": "owner",
		"enforcement": "active",
		"current_user_can_bypass": "never"%s
	}`
	tests := []struct {
		name        string
		bypassField string
		wantVisible bool
		wantActors  int
	}{
		{name: "bypass list withheld from a read-only token", bypassField: ""},
		{name: "no one may bypass", bypassField: `, "bypass_actors": []`, wantVisible: true},
		{
			name: "bypass actors listed",
			bypassField: `, "bypass_actors": [
				{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"},
				{"actor_id": null, "actor_type": "DeployKey", "bypass_mode": "always"},
				{"actor_id": 42, "actor_type": "Team", "bypass_mode": "pull_request"}
			]`,
			wantVisible: true,
			wantActors:  3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/owner/repo/rulesets/20" || r.URL.Query().Get("includes_parents") != "true" {
					t.Errorf("unexpected request: %s", r.URL)
				}
				_, _ = fmt.Fprintf(w, ruleset, tt.bypassField)
			}))
			defer server.Close()

			client := NewClientWithHTTP(server.Client(), server.URL)
			rs, err := client.GetRepoRuleset(context.Background(), "owner", "repo", 20)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rs.ID != 20 || rs.Name != "Default branch baseline" || rs.SourceType != "Organization" ||
				rs.Source != "owner" || rs.Enforcement != RulesetEnforcementActive {
				t.Errorf("ruleset parse wrong: %+v", rs)
			}
			if rs.BypassVisible != tt.wantVisible || len(rs.BypassActors) != tt.wantActors {
				t.Errorf("bypass visible = %v with %d actors, want %v with %d", rs.BypassVisible, len(rs.BypassActors), tt.wantVisible, tt.wantActors)
			}
			if tt.wantActors == 3 {
				deployKey, team := rs.BypassActors[1], rs.BypassActors[2]
				if deployKey.ActorID != nil || deployKey.ActorType != BypassActorDeployKey {
					t.Errorf("deploy key actor = %+v, want no ID", deployKey)
				}
				if team.ActorID == nil || *team.ActorID != 42 || team.BypassMode != "pull_request" {
					t.Errorf("team actor = %+v", team)
				}
			}
		})
	}
}
