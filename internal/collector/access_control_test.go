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

	posture, rec := collectRecorded(t, Config{Organization: "test-org"}, mock, componentsdk.LevelAudit)

	if posture.AccessControl.DefaultRepositoryPermission != "" {
		t.Error("expected DefaultRepositoryPermission empty on permission denial")
	}
	if gapOf(rec, "/access_control/default_repository_permission") == nil {
		t.Error("default_repository_permission has no gap")
	}
	if len(rec.Warnings()) != 0 {
		t.Errorf("warnings = %+v, want none because the gap records the denial", rec.Warnings())
	}
}
