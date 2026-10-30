package collector

import (
	"context"
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

func TestGapsNameThePermissionToGrant(t *testing.T) {
	app := func(scopes ...string) github.Credential {
		return github.Credential{Kind: github.CredentialAppInstallation, ID: "1", Scopes: scopes}
	}
	denied := &github.APIError{StatusCode: http.StatusForbidden, Path: "/orgs/test-org", Operation: "github.org_settings.get"}
	failed := &github.APIError{StatusCode: http.StatusBadGateway, Path: "/orgs/test-org", Operation: "github.org_settings.get"}

	for name, tc := range map[string]struct {
		credential github.Credential
		settings   error
		pointer    string
		warning    string
		missing    string
	}{
		"a GitHub App without the permission": {
			credential: app("metadata:read"),
			settings:   denied,
			pointer:    "/access_control/default_repository_permission",
			warning:    "Grant the GitHub App organization_administration:read.",
			missing:    "organization_administration:read",
		},
		"a GitHub App with the permission": {
			credential: app("metadata:read", "organization_administration:read"),
			settings:   denied,
			pointer:    "/access_control/default_repository_permission",
			warning:    "GitHub refused this although the GitHub App has organization_administration:read.",
		},
		"a token": {
			credential: github.Credential{Kind: github.CredentialToken},
			settings:   denied,
			pointer:    "/access_control/default_repository_permission",
			warning:    "A GitHub App or fine-grained token needs organization_administration:read for this.",
		},
		"an installation token": {
			credential: github.Credential{Kind: github.CredentialInstallationToken},
			settings:   denied,
			pointer:    "/access_control/default_repository_permission",
			warning:    "A GitHub App or fine-grained token needs organization_administration:read for this.",
		},
		"a failure that is no denial": {
			credential: app("metadata:read"),
			settings:   failed,
			pointer:    "/access_control/default_repository_permission",
		},
		"a value withheld from a GitHub App without the permission": {
			credential: app("metadata:read"),
			pointer:    "/access_control/two_factor_required",
			warning:    "Grant the GitHub App organization_administration:read.",
			missing:    "organization_administration:read",
		},
		"a value withheld from a GitHub App with the permission": {
			credential: app("metadata:read", "organization_administration:read"),
			pointer:    "/access_control/two_factor_required",
		},
	} {
		t.Run(name, func(t *testing.T) {
			mock := richMock()
			mock.orgSecurity = &github.OrgSecurity{Credential: tc.credential}
			mock.orgSettingsErr = tc.settings
			rec := &componentsdk.Recorder{}
			c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}, Recorder: rec}, mock)
			if _, err := c.Collect(context.Background(), componentsdk.LevelAudit); err != nil {
				t.Fatal(err)
			}
			var gap *componentsdk.Gap
			for _, g := range rec.Gaps() {
				if g.Path == DetailedPath && g.Pointer == tc.pointer {
					gap = &g
				}
			}
			if gap == nil {
				t.Fatalf("no gap at %s", tc.pointer)
			}
			if gap.Warning != tc.warning || gap.MissingPermission != tc.missing {
				t.Errorf("warning %q and missing permission %q, want %q and %q", gap.Warning, gap.MissingPermission, tc.warning, tc.missing)
			}
		})
	}
}

// Every call the collector names needs a permission GitHub lists, or is one
// that needs none.
func TestOperationPermissionsCoverEveryCall(t *testing.T) {
	needNone := map[string]bool{
		"github.installation_token.create": true,
		"github.orgs.get":                  true,
		"github.users.get":                 true,
	}
	for _, op := range kitOperations {
		if _, ok := operationPermissions[op]; ok == needNone[op] {
			t.Errorf("%s: in operationPermissions %t, but needs a permission %t", op, ok, !needNone[op])
		}
	}
}

func TestReadOnlyNeedsEveryPermissionAtRead(t *testing.T) {
	for _, tc := range []struct {
		scopes []string
		want   bool
	}{
		{[]string{"metadata:read", "members:read"}, true},
		{[]string{"metadata:read", "contents:write"}, false},
		{[]string{"metadata:read", "organization_administration:admin"}, false},
		{nil, false},
	} {
		if got := readOnly(tc.scopes); got != tc.want {
			t.Errorf("readOnly(%v) = %t, want %t", tc.scopes, got, tc.want)
		}
	}
}
