package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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
	relevant := []string{
		"org.add_member", "org.invite_member", "org.remove_member", "repo.create", "protected_branch.update",
		"org.disable_two_factor_requirement", "secret_scanning_push_protection.bypass",
	}
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
			first:  `{"total_count":2,"runners":[{"id":1,"name":"a","busy":false,"labels":[{"name":"self-hosted"}]}]}`,
			second: `{"total_count":2,"runners":[{"id":2,"name":"b","busy":true}]}`,
			list: func(c *Client) (int, int, error) {
				runners, total, err := c.ListOrgRunners(ctx, "org")
				return len(runners), total, err
			},
		},
		{
			name:   "repo runners",
			path:   "/repos/org/repo/actions/runners",
			first:  `{"total_count":2,"runners":[{"id":1,"name":"a","busy":false}]}`,
			second: `{"total_count":2,"runners":[{"id":2,"name":"b","busy":false}]}`,
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
			first:  `{"total_count":2,"installations":[{"app_slug":"a","app_id":1,"suspended_at":null}]}`,
			second: `{"total_count":2,"installations":[{"app_slug":"b","app_id":2,"suspended_at":null}]}`,
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
	items, total, err := client.getPagedTotal(context.Background(), "github.org_runners.list", "/orgs/org/actions/runners?per_page=100", "runners", 1, nil)
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
		{"org webhooks", `{"id":1,"active":true,"events":["push"]}`, HookFetchCap, func(c *Client) (int, bool, error) {
			hooks, more, err := c.ListOrgHooks(ctx, "org")
			return len(hooks), more, err
		}},
		{"repo webhooks", `{"id":1,"active":true,"events":["push"]}`, HookFetchCap, func(c *Client) (int, bool, error) {
			hooks, more, err := c.ListRepoHooks(ctx, "org", "repo")
			return len(hooks), more, err
		}},
		{"deploy keys", `{"id":1,"read_only":true}`, DeployKeyFetchCap, func(c *Client) (int, bool, error) {
			keys, more, err := c.ListRepoDeployKeys(ctx, "org", "repo")
			return len(keys), more, err
		}},
		{"token grants", `{"id":1,"token_expired":false,"token_expires_at":null,"token_last_used_at":null}`, TokenGrantFetchCap, func(c *Client) (int, bool, error) {
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
		_, _ = w.Write([]byte(`[{"id":5,"owner":{"login":"alice"},"token_name":"ci","permissions":{"organization":{"members":"read"},"repository":{"contents":"write","metadata":"read"}},` +
			`"token_expired":false,"token_expires_at":null,"token_last_used_at":null}]`))
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

// GitHub lists a token that expired, until its grant is revoked.
func TestListOrgPATsMarksExpiredTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":5,"token_expired":false,"token_expires_at":"2099-01-01T00:00:00Z","token_last_used_at":null},` +
			`{"id":6,"token_expired":true,"token_expires_at":"2026-01-01T00:00:00Z","token_last_used_at":null}]`))
	}))
	defer server.Close()

	grants, _, err := NewClientWithHTTP(server.Client(), server.URL).ListOrgPATs(context.Background(), "org")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 || grants[0].Expired || !grants[1].Expired {
		t.Errorf("grants = %+v, want the second one expired", grants)
	}
}

// GitHub disables every deploy key when the organization stops allowing
// them, and lists each with enabled false. An answer without the field is
// from before GitHub added it.
func TestListRepoDeployKeysMarksDisabledKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"read_only":true,"enabled":true},{"id":2,"read_only":true,"enabled":false},{"id":3,"read_only":true}]`))
	}))
	defer server.Close()

	keys, _, err := NewClientWithHTTP(server.Client(), server.URL).ListRepoDeployKeys(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0].Disabled || !keys[1].Disabled || keys[2].Disabled {
		t.Errorf("keys = %+v, want only the second one disabled", keys)
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

func TestGetCodeownersInfoReadsAFileOver1MB(t *testing.T) {
	// A CODEOWNERS file of up to 3 MB takes effect. A file over 1 MB is
	// served only under the raw or object media types. Under the object media
	// type its content is empty.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/org/repo/contents/.github/CODEOWNERS" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		if r.Header.Get("Accept") != "application/vnd.github.object+json" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"This API returns blobs up to 1 MB in size."}`))
			return
		}
		_, _ = w.Write([]byte(`{"type":"file","encoding":"none","size":2097152,"content":""}`))
	}))
	defer server.Close()

	present, path, hash, err := NewClientWithHTTP(server.Client(), server.URL).GetCodeownersInfo(context.Background(), "org", "repo", true)
	if err != nil {
		t.Fatal(err)
	}
	if !present || path != ".github/CODEOWNERS" || hash != "" {
		t.Errorf("present %v at %q with hash %q, want present at .github/CODEOWNERS with no hash", present, path, hash)
	}
}

func TestGetCodeownersInfoSkipsADirectory(t *testing.T) {
	// A directory named CODEOWNERS is no CODEOWNERS file, so the search goes
	// on to the next location. A directory comes back as its entries.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/org/repo/contents/.github/CODEOWNERS":
			_, _ = w.Write([]byte(`{"type":"dir","entries":[{"type":"file","name":"a.txt"}]}`))
		case "/repos/org/repo/contents/CODEOWNERS":
			_, _ = w.Write([]byte(`[{"type":"file","name":"b.txt"}]`))
		case "/repos/org/repo/contents/docs/CODEOWNERS":
			_, _ = w.Write([]byte(`{"type":"file","encoding":"base64","size":22,"content":"KiBAdGVzdC1vcmcvc2VjdXJpdHkK\n"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	present, path, _, err := NewClientWithHTTP(server.Client(), server.URL).GetCodeownersInfo(context.Background(), "org", "repo", false)
	if err != nil {
		t.Fatal(err)
	}
	if !present || path != "docs/CODEOWNERS" {
		t.Errorf("present %v at %q, want the docs/CODEOWNERS file past the two directories", present, path)
	}
}

func TestListSecretScanningAlertsReadsTheGenericTypes(t *testing.T) {
	// Without secret_type only the default patterns are listed. The generic
	// types are listed only by name.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		named := r.URL.Query().Get("secret_type")
		switch {
		case named == "":
			_, _ = w.Write([]byte(`[{"number":1,"secret_type":"aws_access_key_id","state":"open"}]`))
		case strings.Contains(named, "rsa_private_key") && strings.Contains(named, "password"):
			_, _ = w.Write([]byte(`[{"number":2,"secret_type":"rsa_private_key","state":"open"},{"number":3,"secret_type":"password","state":"open"}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer server.Close()

	alerts, more, err := NewClientWithHTTP(server.Client(), server.URL).ListSecretScanningAlerts(context.Background(), "org", "repo")
	if err != nil || more {
		t.Fatalf("err %v, more %t", err, more)
	}
	var got []string
	for _, a := range alerts {
		got = append(got, fmt.Sprintf("%d:%s", a.Number, a.SecretType))
	}
	if strings.Join(got, ",") != "1:aws_access_key_id,2:rsa_private_key,3:password" {
		t.Errorf("alerts = %v, want the default alert and both generic alerts", got)
	}
}

func TestListDependabotAlertsAtTheCapKeepsTheMostSevere(t *testing.T) {
	// Alerts are listed newest first, 100 to a page, unless severity or
	// direction is set. Alert 1 is the oldest and the only critical one.
	const total = AlertFetchCap + 100
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var numbers []int
		for n := total; n >= 1; n-- {
			severity := "low"
			if n == 1 {
				severity = "critical"
			}
			if s := q.Get("severity"); s == "" || s == severity {
				numbers = append(numbers, n)
			}
		}
		if q.Get("direction") == "asc" {
			slices.Reverse(numbers)
		}
		page, _ := strconv.Atoi(q.Get("page"))
		page = max(page, 1)
		start, end := min((page-1)*100, len(numbers)), min(page*100, len(numbers))
		if end < len(numbers) {
			q.Set("page", strconv.Itoa(page+1))
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?%s>; rel="next"`, r.Host, r.URL.Path, q.Encode()))
		}
		var items []string
		for _, n := range numbers[start:end] {
			severity := "low"
			if n == 1 {
				severity = "critical"
			}
			items = append(items, fmt.Sprintf(`{"number":%d,"state":"open","security_vulnerability":{"severity":%q}}`, n, severity))
		}
		_, _ = w.Write([]byte("[" + strings.Join(items, ",") + "]"))
	}))
	defer server.Close()

	alerts, more, err := NewClientWithHTTP(server.Client(), server.URL).ListDependabotAlerts(context.Background(), "org", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if !more || len(alerts) != AlertFetchCap {
		t.Fatalf("read %d alerts, more %t; want the cap of %d, marked as possibly holding more", len(alerts), more, AlertFetchCap)
	}
	if alerts[0].Number != 1 || alerts[1].Number != 2 || alerts[len(alerts)-1].Number != AlertFetchCap {
		t.Errorf("read alerts %d, %d, ..., %d; want the critical alert 1, then the oldest low alerts from 2", alerts[0].Number, alerts[1].Number, alerts[len(alerts)-1].Number)
	}
}

// writeAlertPage writes one page of the alerts in numbers, which are newest
// first. direction=asc reverses them, and a page holds 100 alerts. item
// writes alert n.
func writeAlertPage(w http.ResponseWriter, r *http.Request, numbers []int, item func(n int) string) {
	q := r.URL.Query()
	if q.Get("direction") == "asc" {
		slices.Reverse(numbers)
	}
	page, _ := strconv.Atoi(q.Get("page"))
	page = max(page, 1)
	start, end := min((page-1)*100, len(numbers)), min(page*100, len(numbers))
	if end < len(numbers) {
		q.Set("page", strconv.Itoa(page+1))
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?%s>; rel="next"`, r.Host, r.URL.Path, q.Encode()))
	}
	var items []string
	for _, n := range numbers[start:end] {
		items = append(items, item(n))
	}
	_, _ = w.Write([]byte("[" + strings.Join(items, ",") + "]"))
}

// alertCreatedAt is alert n's created_at, one minute after alert n-1's.
func alertCreatedAt(n int) string {
	return time.Date(2026, 1, 1, 0, n, 0, 0, time.UTC).Format(time.RFC3339)
}

func TestListCodeScanningAlertsAtTheCapKeepsTheMostSevere(t *testing.T) {
	// Alerts are numbered oldest first. Alert 1 is the only one of error
	// severity, and alerts 2 to 3000 are notes. The rest have rule severity
	// none, which no severity filter matches.
	const total = AlertFetchCap + 100
	severity := func(n int) string {
		switch {
		case n == 1:
			return "error"
		case n <= 3000:
			return "note"
		}
		return "none"
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var numbers []int
		for n := total; n >= 1; n-- {
			if s := r.URL.Query().Get("severity"); s == "" || s == severity(n) {
				numbers = append(numbers, n)
			}
		}
		writeAlertPage(w, r, numbers, func(n int) string {
			return fmt.Sprintf(`{"number":%d,"state":"open","created_at":%q,"rule":{"id":"go/rule","severity":%q}}`, n, alertCreatedAt(n), severity(n))
		})
	}))
	defer server.Close()

	alerts, more, err := NewClientWithHTTP(server.Client(), server.URL).ListCodeScanningAlerts(context.Background(), "org", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if !more || len(alerts) != AlertFetchCap {
		t.Fatalf("read %d alerts, more %t; want the cap of %d, marked as possibly holding more", len(alerts), more, AlertFetchCap)
	}
	for i, a := range alerts {
		if a.Number != i+1 {
			t.Fatalf("alert %d is number %d; want the error alert, then the notes, then the oldest alerts with no severity", i, a.Number)
		}
	}
}

func TestListSecretScanningAlertsAtTheCapKeepsTheOldest(t *testing.T) {
	// Alerts are numbered oldest first. Only the generic types list alerts 1
	// and 2. The default patterns list the rest.
	const total = AlertFetchCap + 100
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		numbers := []int{2, 1}
		if r.URL.Query().Get("secret_type") == "" {
			numbers = nil
			for n := total; n >= 3; n-- {
				numbers = append(numbers, n)
			}
		}
		writeAlertPage(w, r, numbers, func(n int) string {
			return fmt.Sprintf(`{"number":%d,"secret_type":"aws_access_key_id","state":"open","created_at":%q}`, n, alertCreatedAt(n))
		})
	}))
	defer server.Close()

	alerts, more, err := NewClientWithHTTP(server.Client(), server.URL).ListSecretScanningAlerts(context.Background(), "org", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if !more || len(alerts) != AlertFetchCap {
		t.Fatalf("read %d alerts, more %t; want the cap of %d, marked as possibly holding more", len(alerts), more, AlertFetchCap)
	}
	for i, a := range alerts {
		if a.Number != i+1 {
			t.Fatalf("alert %d is number %d; want the oldest alerts of both lists, oldest first", i, a.Number)
		}
	}
}
