package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestGrantsNamePermissionsTheGitHubAppLacks(t *testing.T) {
	denied := func(op string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/orgs/test-org/members", nil)
		req = req.WithContext(componentsdk.WithOperation(req.Context(), componentsdk.Operation{Name: op, Permission: ReadPermission(op)}))
		return &http.Response{StatusCode: http.StatusForbidden, Request: req}
	}
	app := Credential{Kind: CredentialAppInstallation, Scopes: []string{"members:read", "metadata:read"}}
	for _, tc := range []struct {
		name       string
		credential *Credential
		op         string
		want       bool
	}{
		{"an App without the permission", &app, "github.org_settings.get", true},
		{"an App with the permission", &app, "github.org_members.list", false},
		{"a token", &Credential{Kind: CredentialToken}, "github.org_settings.get", false},
		{"an installation token", &Credential{Kind: CredentialInstallationToken}, "github.org_settings.get", false},
		{"a call that needs no permission", &app, "github.orgs.get", false},
		{"before sign-in", nil, "github.org_settings.get", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var g Grants
			if tc.credential != nil {
				g.SignedIn(*tc.credential)
			}
			if got := g.NamesPermission(denied(tc.op), nil); got != tc.want {
				t.Errorf("NamesPermission = %t, want %t", got, tc.want)
			}
		})
	}
}

// Each call carries the permission GitHub lists for it, so the collector
// result names it with the operation.
func TestCallsDeclareTheirPermission(t *testing.T) {
	var seen []componentsdk.Operation
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		op, _ := componentsdk.OperationOf(req.Context())
		seen = append(seen, op)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`[]`)), Request: req}, nil
	})}
	if _, _, err := NewClientWithHTTP(client, "https://api.github.com").ListRepoDeployKeys(context.Background(), "test-org", "repo"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Name != "github.deploy_keys.list" || seen[0].Permission != "administration:read" {
		t.Errorf("operations = %+v, want github.deploy_keys.list with administration:read", seen)
	}
}

// Listing the organization's roles needs Custom organization roles, and
// listing a role's holders needs Members, as GitHub's "Permissions required
// for GitHub Apps" lists them.
func TestOrganizationRoleCallsDeclareTheirPermission(t *testing.T) {
	var seen []componentsdk.Operation
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		op, _ := componentsdk.OperationOf(req.Context())
		seen = append(seen, op)
		body := `[]`
		if strings.HasSuffix(req.URL.Path, "/organization-roles") {
			body = `{"total_count":0,"roles":[]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
	c := NewClientWithHTTP(client, "https://api.github.com")
	if _, err := c.ListOrgRoles(context.Background(), "test-org"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ListOrgRoleUsers(context.Background(), "test-org", 8136); err != nil {
		t.Fatal(err)
	}
	want := []string{"github.org_roles.list organization_custom_org_roles:read", "github.org_role_users.list members:read"}
	var got []string
	for _, op := range seen {
		got = append(got, op.Name+" "+op.Permission)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("operations = %v, want %v", got, want)
	}
}
