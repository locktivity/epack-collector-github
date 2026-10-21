package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestHostOnly_StripsPathQueryAndScheme(t *testing.T) {
	cases := map[string]string{
		"https://hooks.example.com/webhook?secret=abc123": "hooks.example.com",
		"https://ci.example.com:8443/path/to/hook":        "ci.example.com:8443",
		"http://internal/notify":                          "internal",
		"not a url":                                       "",
		"":                                                "",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsSecurityRelevantAction(t *testing.T) {
	relevant := []string{"member_add", "repo.create", "protected_branch.update", "org.disable_two_factor_requirement"}
	for _, a := range relevant {
		if !isSecurityRelevantAction(a) {
			t.Errorf("isSecurityRelevantAction(%q) = false, want true", a)
		}
	}
	irrelevant := []string{"git.clone", "issue.comment", "project.create"}
	for _, a := range irrelevant {
		if isSecurityRelevantAction(a) {
			t.Errorf("isSecurityRelevantAction(%q) = true, want false", a)
		}
	}
}

func TestIs403FeatureDisabled(t *testing.T) {
	// Feature-disabled 403 bodies GitHub returns when scanning/Dependabot is off.
	featureOff := []string{
		`{"message":"Advanced Security must be enabled for this repository to use code scanning."}`,
		`{"message":"Dependabot alerts are disabled for this repository."}`,
		`{"message":"Secret scanning is disabled on this repository."}`,
		`{"message":"code scanning is not enabled for this repository"}`,
	}
	for _, b := range featureOff {
		if !is403FeatureDisabled(b) {
			t.Errorf("is403FeatureDisabled(%q) = false, want true", b)
		}
	}

	// Genuine missing-permission 403 body.
	permission := `{"message":"Resource not accessible by integration","documentation_url":"..."}`
	if is403FeatureDisabled(permission) {
		t.Errorf("is403FeatureDisabled(%q) = true, want false (this is a permission error)", permission)
	}
}

// pagedServer serves a two-page list at path with GitHub's Link header and
// counts the requests it answers.
func pagedServer(t *testing.T, path, first, second string, requests *int) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		switch {
		case r.URL.Path == path && r.URL.Query().Get("page") == "":
			next := fmt.Sprintf("%s/organizations/1/next?per_page=100&page=2", server.URL)
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next", <%s>; rel="last"`, next, next))
			_, _ = w.Write([]byte(first))
		case r.URL.Path == "/organizations/1/next" && r.URL.Query().Get("page") == "2":
			_, _ = w.Write([]byte(second))
		default:
			t.Errorf("unexpected request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestInventoryListsFollowPagination(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		path          string
		first, second string
		list          func(*Client) (int, int, error)
	}{
		{
			name:   "org runners",
			path:   "/orgs/org/actions/runners",
			first:  `{"total_count":2,"runners":[{"id":1,"name":"a","labels":[{"name":"self-hosted"}]}]}`,
			second: `{"total_count":2,"runners":[{"id":2,"name":"b"}]}`,
			list: func(c *Client) (int, int, error) {
				runners, total, err := c.ListOrgRunners(ctx, "org")
				return len(runners), total, err
			},
		},
		{
			name:   "repo runners",
			path:   "/repos/org/repo/actions/runners",
			first:  `{"total_count":2,"runners":[{"id":1,"name":"a"}]}`,
			second: `{"total_count":2,"runners":[{"id":2,"name":"b"}]}`,
			list: func(c *Client) (int, int, error) {
				runners, total, err := c.ListRepoRunners(ctx, "org", "repo")
				return len(runners), total, err
			},
		},
		{
			name:   "org secrets",
			path:   "/orgs/org/actions/secrets",
			first:  `{"total_count":2,"secrets":[{"name":"A"}]}`,
			second: `{"total_count":2,"secrets":[{"name":"B"}]}`,
			list: func(c *Client) (int, int, error) {
				names, total, err := c.ListOrgActionsSecretNames(ctx, "org")
				return len(names), total, err
			},
		},
		{
			name:   "installations",
			path:   "/orgs/org/installations",
			first:  `{"total_count":2,"installations":[{"app_slug":"a","app_id":1}]}`,
			second: `{"total_count":2,"installations":[{"app_slug":"b","app_id":2}]}`,
			list: func(c *Client) (int, int, error) {
				installs, total, err := c.ListOrgInstallations(ctx, "org")
				return len(installs), total, err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := pagedServer(t, tt.path, tt.first, tt.second, &requests)
			read, total, err := tt.list(NewClientWithHTTP(server.Client(), server.URL))
			if err != nil {
				t.Fatal(err)
			}
			if read != 2 || total != 2 || requests != 2 {
				t.Errorf("read %d of %d in %d requests, want 2 of 2 in 2", read, total, requests)
			}
		})
	}
}

func TestGetPagedTotalStopsAtTheCap(t *testing.T) {
	requests := 0
	server := pagedServer(t, "/orgs/org/actions/runners",
		`{"total_count":3,"runners":[{"id":1}]}`, `{"total_count":3,"runners":[{"id":2},{"id":3}]}`, &requests)
	client := NewClientWithHTTP(server.Client(), server.URL)
	items, total, err := client.getPagedTotal(context.Background(), "github.org_runners.list", "/orgs/org/actions/runners?per_page=100", "runners", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || total != 3 || requests != 1 {
		t.Errorf("read %d of %d in %d requests, want 1 of 3 in 1", len(items), total, requests)
	}
}

// endlessServer answers every request with a page of size copies of item and
// a link to another page, so a list stops only at its cap.
func endlessServer(t *testing.T, item string, size int) *httptest.Server {
	t.Helper()
	page := "[" + strings.TrimSuffix(strings.Repeat(item+",", size), ",") + "]"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=next>; rel="next"`, server.URL, r.URL.Path))
		_, _ = w.Write([]byte(page))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestListsAtTheCapSayTheyMayHoldMore(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		item     string
		fetchCap int
		list     func(*Client) (int, bool, error)
	}{
		{"org webhooks", `{"id":1}`, HookFetchCap, func(c *Client) (int, bool, error) {
			hooks, more, err := c.ListOrgHooks(ctx, "org")
			return len(hooks), more, err
		}},
		{"repo webhooks", `{"id":1}`, HookFetchCap, func(c *Client) (int, bool, error) {
			hooks, more, err := c.ListRepoHooks(ctx, "org", "repo")
			return len(hooks), more, err
		}},
		{"deploy keys", `{"id":1}`, DeployKeyFetchCap, func(c *Client) (int, bool, error) {
			keys, more, err := c.ListRepoDeployKeys(ctx, "org", "repo")
			return len(keys), more, err
		}},
		{"token grants", `{"id":1}`, TokenGrantFetchCap, func(c *Client) (int, bool, error) {
			grants, more, err := c.ListOrgPATs(ctx, "org")
			return len(grants), more, err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := endlessServer(t, tt.item, 1000)
			read, more, err := tt.list(NewClientWithHTTP(server.Client(), server.URL))
			if err != nil {
				t.Fatal(err)
			}
			if read != tt.fetchCap || !more {
				t.Errorf("read %d, more %t; want the cap of %d, marked as possibly holding more", read, more, tt.fetchCap)
			}
		})
	}
}

func TestGetOrgMembershipMarksRostersAtTheCap(t *testing.T) {
	server := endlessServer(t, `{"login":"someone"}`, 10000)
	m, err := NewClientWithHTTP(server.Client(), server.URL).GetOrgMembership(context.Background(), "org")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Members) != MemberFetchCap || !m.MembersMore || !m.AdminsMore || !m.OutsideCollaboratorsMore {
		t.Errorf("read %d members; more: members %t, admins %t, outside collaborators %t; want every roster marked at the cap",
			len(m.Members), m.MembersMore, m.AdminsMore, m.OutsideCollaboratorsMore)
	}
	// Members past the cap of the roster without two-factor would read as
	// having it on, so the roster is not used.
	if m.TwoFADisabled != nil || m.TwoFAErr != nil {
		t.Errorf("TwoFADisabled has %d logins (err %v), want none and no error", len(m.TwoFADisabled), m.TwoFAErr)
	}
}

func TestListOrgPATsKeepsAccessLevels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":5,"owner":{"login":"alice"},"token_name":"ci","permissions":{"organization":{"members":"read"},"repository":{"contents":"write","metadata":"read"}}}]`))
	}))
	defer server.Close()

	grants, more, err := NewClientWithHTTP(server.Client(), server.URL).ListOrgPATs(context.Background(), "org")
	if err != nil {
		t.Fatal(err)
	}
	if more || len(grants) != 1 || strings.Join(grants[0].Permissions, ",") != "contents:write,members:read,metadata:read" {
		t.Errorf("grants = %+v, more %t; want one grant with contents:write, members:read, and metadata:read", grants, more)
	}
}

func TestGetPagedTotalNeedsTheListAndTheTotal(t *testing.T) {
	for _, body := range []string{`{"total_count":1}`, `{"runners":[]}`, `{"total_count":1,"runners":null}`, `{"total_count":null,"runners":[]}`, `null`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		client := NewClientWithHTTP(server.Client(), server.URL)
		_, _, err := client.ListOrgRunners(context.Background(), "org")
		server.Close()
		if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
			t.Errorf("%s: Classify(%v) = %s, want invalid_response", body, err, got)
		}
	}
}

func TestGetCodeownersInfoPicksTheFileGitHubUses(t *testing.T) {
	// GitHub reads .github/, then the root, then docs/, and uses the first
	// CODEOWNERS it finds.
	file := `{"type":"file","encoding":"base64","size":22,"content":"KiBAdGVzdC1vcmcvc2VjdXJpdHkK\n"}`
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/repos/org/repo/contents/CODEOWNERS", "/repos/org/repo/contents/docs/CODEOWNERS":
			_, _ = w.Write([]byte(file))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	defer server.Close()

	present, path, _, err := NewClientWithHTTP(server.Client(), server.URL).GetCodeownersInfo(context.Background(), "org", "repo", false)
	if err != nil {
		t.Fatal(err)
	}
	if !present || path != "CODEOWNERS" {
		t.Errorf("present %v at %q, want the root CODEOWNERS", present, path)
	}
	if len(requested) != 2 {
		t.Errorf("requested %v, want .github/CODEOWNERS then CODEOWNERS", requested)
	}
}
