package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ssoServer answers the SAML identities query with pages, one per call, and
// counts the calls.
func ssoServer(t *testing.T, pages ...string) (*Client, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/graphql" || !strings.Contains(string(body), "samlIdentityProvider") {
			t.Errorf("unexpected request %s %s", r.URL.Path, body)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if calls > 0 && !strings.Contains(string(body), `"cursor":"page-2"`) {
			t.Errorf("request %d carries no cursor for the second page: %s", calls+1, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pages[min(calls, len(pages)-1)]))
		calls++
	}))
	t.Cleanup(server.Close)
	return NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql"), &calls
}

func TestFetchOrgSSOCountsLinkedAndSCIMIdentities(t *testing.T) {
	client, calls := ssoServer(t,
		`{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"nodes":[{"samlIdentity":{"nameId":"alice@example.com"},"scimIdentity":{"groups":null},"user":{"login":"alice"}},{"samlIdentity":null,"scimIdentity":{"groups":[]},"user":{"login":"bob"}}],"pageInfo":{"hasNextPage":true,"endCursor":"page-2"}}}}}}`,
		`{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"nodes":[{"samlIdentity":{"nameId":"dana@example.com"},"scimIdentity":null,"user":null}],"pageInfo":{"hasNextPage":false,"endCursor":""}}}}}}`,
	)
	sso, err := client.FetchOrgSSO(context.Background(), "test-org")
	if err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Errorf("calls = %d, want both pages", *calls)
	}
	if !sso.Configured || sso.LinkedMembers != 2 || sso.SCIMMembers != 2 || sso.More {
		t.Errorf("sso = %+v, want configured with 2 linked and 2 SCIM identities", sso)
	}
	// bob's identity has no SAML record, and the second SAML identity names
	// no member.
	if len(sso.NameIDs) != 1 || sso.NameIDs["alice"] != "alice@example.com" {
		t.Errorf("NameIDs = %v, want alice's alone", sso.NameIDs)
	}
}

func TestFetchOrgSSOSelectsTheNameIDAndLogin(t *testing.T) {
	for _, field := range []string{"samlIdentity{nameId}", "user{login}", "membersOnly: true"} {
		if !strings.Contains(samlIdentitiesQuery, field) {
			t.Errorf("the SAML query does not select %s", field)
		}
	}
}

func TestFetchOrgSSOWithoutAProviderIsNotConfigured(t *testing.T) {
	client, _ := ssoServer(t, `{"data":{"organization":{"samlIdentityProvider":null}}}`)
	sso, err := client.FetchOrgSSO(context.Background(), "test-org")
	if err != nil {
		t.Fatal(err)
	}
	if sso.Configured || sso.LinkedMembers != 0 || sso.SCIMMembers != 0 {
		t.Errorf("sso = %+v, want not configured", sso)
	}
}

func TestFetchOrgSSOForbiddenIsADenial(t *testing.T) {
	client, _ := ssoServer(t, `{"data":{"organization":{"samlIdentityProvider":null}},"errors":[{"type":"FORBIDDEN","message":"Resource not accessible by integration"}]}`)
	_, err := client.FetchOrgSSO(context.Background(), "test-org")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err = %v, want a permission denial", err)
	}
}

func TestFetchOrgSSOWithoutAnIdentityListIsInvalid(t *testing.T) {
	client, _ := ssoServer(t, `{"data":{"organization":{"samlIdentityProvider":{}}}}`)
	if _, err := client.FetchOrgSSO(context.Background(), "test-org"); err == nil {
		t.Fatal("a provider with no external identity list was read as valid")
	}
}

func TestGetOrgRostersReadsNoNamesOrInvitations(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/orgs/test-org/members" && r.URL.Query().Get("role") == "admin":
			_, _ = w.Write([]byte(`[{"login":"alice"}]`))
		case r.URL.Path == "/orgs/test-org/members" && r.URL.Query().Get("filter") == "2fa_disabled":
			_, _ = w.Write([]byte(`[{"login":"bob"}]`))
		case r.URL.Path == "/orgs/test-org/members":
			_, _ = w.Write([]byte(`[{"login":"alice"},{"login":"bob"}]`))
		case r.URL.Path == "/orgs/test-org/outside_collaborators" && r.URL.Query().Get("filter") == "2fa_disabled":
			_, _ = w.Write([]byte(`[{"login":"carol"}]`))
		case r.URL.Path == "/orgs/test-org/outside_collaborators":
			_, _ = w.Write([]byte(`[{"login":"carol"},{"login":"dan"}]`))
		default:
			t.Errorf("unexpected request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	m, err := NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql").GetOrgRosters(context.Background(), "test-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Errorf("requests = %v, want the five rosters", paths)
	}
	if len(m.Members) != 2 || len(m.Admins) != 1 || len(m.OutsideCollaborators) != 2 || !m.TwoFADisabled["bob"] {
		t.Errorf("rosters = %+v", m)
	}
	if len(m.CollaboratorsTwoFADisabled) != 1 || !m.CollaboratorsTwoFADisabled["carol"] || m.CollaboratorsTwoFAErr != nil {
		t.Errorf("outside collaborators without two-factor authentication = %v, %v, want carol", m.CollaboratorsTwoFADisabled, m.CollaboratorsTwoFAErr)
	}
	if m.Names != nil || m.PendingInvitations != 0 {
		t.Errorf("names %v and invitations %d, want neither read", m.Names, m.PendingInvitations)
	}
}

// With no outside collaborators, none can lack two-factor authentication, so
// the run does not ask.
func TestGetOrgRostersSkipsTheCollaboratorTwoFactorListWithNoCollaborators(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/orgs/test-org/members":
			_, _ = w.Write([]byte(`[{"login":"alice"}]`))
		case r.URL.Path == "/orgs/test-org/outside_collaborators" && r.URL.Query().Get("filter") == "":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	m, err := NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql").GetOrgRosters(context.Background(), "test-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 {
		t.Errorf("requests = %v, want four rosters and no outside collaborator two-factor list", paths)
	}
	if m.CollaboratorsTwoFADisabled == nil || len(m.CollaboratorsTwoFADisabled) != 0 || m.CollaboratorsTwoFAErr != nil {
		t.Errorf("outside collaborators without two-factor authentication = %v, %v, want an empty set", m.CollaboratorsTwoFADisabled, m.CollaboratorsTwoFAErr)
	}
}

func TestGetOrgRostersKeepsTheCollaboratorTwoFactorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/orgs/test-org/outside_collaborators" && r.URL.Query().Get("filter") == "2fa_disabled":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
		case r.URL.Path == "/orgs/test-org/outside_collaborators":
			_, _ = w.Write([]byte(`[{"login":"carol"}]`))
		default:
			_, _ = w.Write([]byte(`[{"login":"alice"}]`))
		}
	}))
	defer server.Close()

	m, err := NewClientWithGraphQL(server.Client(), server.URL, server.URL+"/graphql").GetOrgRosters(context.Background(), "test-org")
	if err != nil {
		t.Fatal(err)
	}
	if m.CollaboratorsTwoFADisabled != nil || !errors.Is(m.CollaboratorsTwoFAErr, ErrPermissionDenied) {
		t.Errorf("outside collaborators without two-factor authentication = %v, %v, want a permission denial", m.CollaboratorsTwoFADisabled, m.CollaboratorsTwoFAErr)
	}
}

func TestListCodeScanningAlertsReadsTheSecuritySeverity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"number":1,"state":"open","created_at":"2026-01-01T00:00:00Z","rule":{"id":"go/sql-injection","severity":"error","security_severity_level":"critical"}},
			{"number":2,"state":"open","created_at":"2026-01-02T00:00:00Z","rule":{"id":"go/unused-variable","severity":"note","security_severity_level":null}}
		]`))
	}))
	defer server.Close()

	alerts, _, err := NewClientWithHTTP(server.Client(), server.URL).ListCodeScanningAlerts(context.Background(), "org", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 || alerts[0].SecuritySeverity != "critical" || alerts[1].SecuritySeverity != "" {
		t.Errorf("alerts = %+v, want critical for the security query and none for the other", alerts)
	}
}
