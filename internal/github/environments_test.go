package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// prodEnvironmentJSON mirrors the live List-environments payload shape: a
// branch_policy rule, a required_reviewers rule with a team and a user, a
// wait timer, and a protected-branches deployment branch policy.
const prodEnvironmentJSON = `{
	"id": 1,
	"name": "production",
	"created_at": "2026-02-01T00:00:00Z",
	"updated_at": "2026-02-02T00:00:00Z",
	"can_admins_bypass": true,
	"protection_rules": [
		{"id": 10, "type": "branch_policy"},
		{
			"id": 11,
			"type": "required_reviewers",
			"prevent_self_review": true,
			"reviewers": [
				{"type": "Team", "reviewer": {"slug": "release-approvers", "name": "Release Approvers", "type": "organization"}},
				{"type": "User", "reviewer": {"login": "alice", "type": "User"}}
			]
		},
		{"id": 12, "type": "wait_timer", "wait_timer": 30}
	],
	"deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false}
}`

func TestListRepoEnvironments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/environments" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"total_count": 2, "environments": [%s, {"id": 2, "name": "scratch"}]}`, prodEnvironmentJSON)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	envs, total, err := client.ListRepoEnvironments(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 || len(envs) != 2 {
		t.Fatalf("total = %d, len = %d, want 2/2", total, len(envs))
	}

	prod := envs[0]
	if prod.Name != "production" || !prod.HasRequiredReviewers || !prod.PreventSelfReview {
		t.Errorf("production parse wrong: %+v", prod)
	}
	if prod.WaitTimerMinutes != 30 {
		t.Errorf("WaitTimerMinutes = %d, want 30", prod.WaitTimerMinutes)
	}
	if prod.BranchPolicy != BranchPolicyProtected {
		t.Errorf("BranchPolicy = %q, want %q", prod.BranchPolicy, BranchPolicyProtected)
	}
	if prod.CanAdminsBypass == nil || !*prod.CanAdminsBypass {
		t.Error("CanAdminsBypass should be true")
	}
	if len(prod.Reviewers) != 2 {
		t.Fatalf("reviewers = %+v, want 2", prod.Reviewers)
	}
	if prod.Reviewers[0].Type != "Team" || prod.Reviewers[0].Slug != "release-approvers" || prod.Reviewers[0].Name != "Release Approvers" {
		t.Errorf("team reviewer wrong: %+v", prod.Reviewers[0])
	}
	if prod.Reviewers[1].Type != "User" || prod.Reviewers[1].Login != "alice" {
		t.Errorf("user reviewer wrong: %+v", prod.Reviewers[1])
	}

	// An environment with no rules and no branch policy: open to any branch,
	// bypass flag unknown when the API omits it.
	scratch := envs[1]
	if scratch.HasRequiredReviewers || scratch.WaitTimerMinutes != 0 {
		t.Errorf("scratch should have no gates: %+v", scratch)
	}
	if scratch.BranchPolicy != BranchPolicyAny {
		t.Errorf("scratch BranchPolicy = %q, want %q", scratch.BranchPolicy, BranchPolicyAny)
	}
	if scratch.CanAdminsBypass != nil {
		t.Error("absent can_admins_bypass must stay nil, not read as false")
	}
}

func TestListRepoEnvironments_Pagination(t *testing.T) {
	pageItem := func(i int) string {
		return fmt.Sprintf(`{"id": %d, "name": "preview-%03d"}`, i, i)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var items []string
		switch r.URL.Query().Get("page") {
		case "1":
			for i := 0; i < 100; i++ {
				items = append(items, pageItem(i))
			}
		case "2":
			for i := 100; i < 150; i++ {
				items = append(items, pageItem(i))
			}
		default:
			t.Errorf("unexpected page: %s", r.URL.RawQuery)
		}
		_, _ = fmt.Fprintf(w, `{"total_count": 150, "environments": [%s]}`, strings.Join(items, ","))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	envs, total, err := client.ListRepoEnvironments(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requests != 2 {
		t.Errorf("requests = %d, want 2", requests)
	}
	if total != 150 || len(envs) != 150 {
		t.Errorf("total = %d, len = %d, want 150/150", total, len(envs))
	}
}

func TestListRepoEnvironments_PermissionDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message": "Resource not accessible by integration"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, _, err := client.ListRepoEnvironments(context.Background(), "owner", "repo")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("err = %v, want ErrPermissionDenied", err)
	}
}

func TestListRepoEnvironments_NotFoundIsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	envs, total, err := client.ListRepoEnvironments(context.Background(), "owner", "repo")
	if err != nil || total != 0 || len(envs) != 0 {
		t.Errorf("404 should mean zero environments, got %d/%d/%v", len(envs), total, err)
	}
}

func TestListEnvironmentBranchPolicies_EscapesEnvironmentName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/repos/owner/repo/environments/production%2Feu/deployment-branch-policies" {
			t.Errorf("unexpected path: %s", r.URL.EscapedPath())
		}
		_, _ = w.Write([]byte(`{"total_count": 2, "branch_policies": [
			{"id": 1, "name": "release/*", "type": "branch"},
			{"id": 2, "name": "v*", "type": "tag"}
		]}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	patterns, err := client.ListEnvironmentBranchPolicies(context.Background(), "owner", "repo", "production/eu")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patterns) != 2 || patterns[0].Name != "release/*" || patterns[0].Type != "branch" || patterns[1].Type != "tag" {
		t.Errorf("patterns = %+v", patterns)
	}
}

func TestListEnvironmentProtectionApps_KeepsEnabledOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total_count": 2, "custom_deployment_protection_rules": [
			{"id": 1, "enabled": true, "app": {"id": 100, "slug": "deploy-gate"}},
			{"id": 2, "enabled": false, "app": {"id": 101, "slug": "old-gate"}}
		]}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	apps, err := client.ListEnvironmentProtectionApps(context.Background(), "owner", "repo", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(apps) != 1 || apps[0] != "deploy-gate" {
		t.Errorf("apps = %v, want [deploy-gate]", apps)
	}
}
