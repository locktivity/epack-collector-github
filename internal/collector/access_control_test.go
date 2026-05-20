package collector

import (
	"context"
	"testing"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

func newAccessControlMock() *mockGitHubClient {
	return &mockGitHubClient{
		orgSecurity:  &github.OrgSecurity{TwoFactorRequired: boolPtr(true)},
		repositories: []github.Repository{},
		orgSettings: &github.OrgSettings{
			DefaultRepositoryPermission:  "read",
			MembersCanCreateRepositories: boolPtr(false),
		},
	}
}

func TestAccessControl_TrustOmitsAuditFields(t *testing.T) {
	c := NewWithClient(Config{Organization: "test-org"}, newAccessControlMock())

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	if posture.AccessControl.DefaultRepositoryPermission != "" {
		t.Errorf("trust DefaultRepositoryPermission = %q, want empty", posture.AccessControl.DefaultRepositoryPermission)
	}
	if posture.AccessControl.MembersCanCreateRepositories != nil {
		t.Errorf("trust MembersCanCreateRepositories = %v, want nil", posture.AccessControl.MembersCanCreateRepositories)
	}
}

func TestAccessControl_AuditPopulatesFields(t *testing.T) {
	c := NewWithClient(Config{Organization: "test-org"}, newAccessControlMock())

	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	if posture.AccessControl.DefaultRepositoryPermission != "read" {
		t.Errorf("DefaultRepositoryPermission = %q, want read", posture.AccessControl.DefaultRepositoryPermission)
	}
	if posture.AccessControl.MembersCanCreateRepositories == nil || *posture.AccessControl.MembersCanCreateRepositories {
		t.Errorf("MembersCanCreateRepositories = %v, want false", posture.AccessControl.MembersCanCreateRepositories)
	}
}

func TestAccessControl_PermissionDeniedRecordsDiagnostic(t *testing.T) {
	mock := newAccessControlMock()
	mock.orgSettingsErr = github.ErrPermissionDenied

	c := NewWithClient(Config{Organization: "test-org"}, mock)

	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	if posture.AccessControl.DefaultRepositoryPermission != "" {
		t.Error("expected DefaultRepositoryPermission empty on permission denial")
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.PermissionErrors) == 0 {
		t.Fatal("expected a permission-denied diagnostic")
	}
	found := false
	for _, e := range posture.Diagnostics.PermissionErrors {
		if contains(e, "access_control") && contains(e, "organization_administration:read") {
			found = true
		}
	}
	if !found {
		t.Errorf("diagnostics = %v, want one naming access_control + organization_administration:read", posture.Diagnostics.PermissionErrors)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
