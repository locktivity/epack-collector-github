package collector

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// accessAt runs the mock at level with both new artifacts collected and
// returns the access-posture artifact and the gaps.
func accessAt(t *testing.T, level componentsdk.Level, mock *mockGitHubClient) (*AccessPosture, []componentsdk.Gap) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{
		Organization: "test-org", IncludePatterns: []string{"*"}, Recorder: rec,
		CollectAccess: true, CollectVulns: true,
		Now: func() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) },
	}, mock)
	posture, err := c.Collect(t.Context(), level)
	if err != nil {
		t.Fatal(err)
	}
	if posture.access == nil {
		t.Fatal("no access-posture artifact")
	}
	return posture.access, rec.Gaps()
}

func accessGap(gaps []componentsdk.Gap, pointer string) *componentsdk.Gap {
	for i, g := range gaps {
		if g.Path == AccessPath && g.Pointer == pointer {
			return &gaps[i]
		}
	}
	return nil
}

func wantPct(t *testing.T, name string, got Reading[int], want int) {
	t.Helper()
	if !got.Read || got.Value == nil || *got.Value != want {
		t.Errorf("%s = %+v, want %d", name, got, want)
	}
}

func wantNull(t *testing.T, name string, got Reading[int]) {
	t.Helper()
	if !got.Read || got.Value != nil {
		t.Errorf("%s = %+v, want null", name, got)
	}
}

func wantFlag(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil || *got != want {
		t.Errorf("%s = %v, want %t", name, got, want)
	}
}

// The first App access check: the organization requires two-factor
// authentication. SAML enforcement is left out, since GitHub reports it only
// to enterprise owners.
func TestAccessSignInTakesTheTwoFactorRequirement(t *testing.T) {
	for _, required := range []bool{true, false} {
		mock := richMock()
		mock.orgSecurity.TwoFactorRequired = boolPtr(required)
		a, gaps := accessAt(t, componentsdk.LevelTrust, mock)
		wantFlag(t, "mfa_required", a.SignIn.MFARequired, required)
		if g := accessGap(gaps, "/sign_in/sso_required"); g == nil || g.Code != componentsdk.CodeNotRead || !strings.Contains(g.Detail, "EnterpriseOwnerInfo") {
			t.Errorf("sso_required gap = %+v, want not_read naming the enterprise object", g)
		}
	}
}

func TestAccessSignInReadsSAML(t *testing.T) {
	mock := richMock()
	mock.sso = &github.OrgSSO{Configured: true, LinkedMembers: 1, SCIMMembers: 0}
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	wantFlag(t, "sso_configured", a.SignIn.SSOConfigured, true)
	wantFlag(t, "scim_enabled", a.SignIn.SCIMEnabled, false)
	if a.Members.SSOMemberCount == nil || *a.Members.SSOMemberCount != 1 {
		t.Errorf("sso_member_count = %v, want 1", a.Members.SSOMemberCount)
	}
	wantPct(t, "sso_coverage_pct", a.Members.SSOCoveragePct, 33) // 1 of alice, bob, carol, rounded down

	mock.sso, mock.ssoErr = nil, componentsdk.CodeError(componentsdk.CodePermissionDenied, github.ErrPermissionDenied)
	a, gaps := accessAt(t, componentsdk.LevelAudit, mock)
	if a.SignIn.SSOConfigured != nil || a.Members.SSOMemberCount != nil || a.Members.SSOCoveragePct.Read {
		t.Errorf("sign-in %+v, want the SAML values left out", a.SignIn)
	}
	if g := accessGap(gaps, "/sign_in/sso_configured"); g == nil || g.Code != componentsdk.CodePermissionDenied {
		t.Errorf("sso_configured gap = %+v, want permission_denied", g)
	}
}

// The second App access check: admins who sign in with two-factor
// authentication, over all admins. With the admin base permission, both
// members are admins.
func TestAccessAdminsMFAComesFromTheTwoFactorList(t *testing.T) {
	mock := richMock()
	mock.orgSecurity.DefaultRepositoryPermission = "admin"
	mock.membership.TwoFADisabled = map[string]bool{"bob": true}
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	wantFlag(t, "local_admins_present", a.Admins.LocalAdminsPresent, true)
	if a.Admins.LocalAdminCount == nil || *a.Admins.LocalAdminCount != 2 || a.Admins.LocalMFAAdminCount == nil || *a.Admins.LocalMFAAdminCount != 1 {
		t.Errorf("admins = %+v, want 1 of 2 admins with MFA", a.Admins)
	}
	wantPct(t, "local_admin_mfa_coverage_pct", a.Admins.LocalAdminMFACoveragePct, 50)
	wantPct(t, "admin_share_pct", a.Admins.AdminSharePct, 67) // 2 of 3 people, rounded up
}

func TestAccessAdminsMFAWithNoAdminsIsNull(t *testing.T) {
	mock := richMock()
	mock.membership.Members, mock.membership.Admins = nil, nil
	a, _ := accessAt(t, componentsdk.LevelTrust, mock)
	wantFlag(t, "local_admins_present", a.Admins.LocalAdminsPresent, false)
	wantNull(t, "local_admin_mfa_coverage_pct", a.Admins.LocalAdminMFACoveragePct)
	if a.Admins.AdminCount != nil {
		t.Errorf("admin_count = %v at trust, want it left out", *a.Admins.AdminCount)
	}
}

func TestAccessAdminsMFAUnknownWithoutTheTwoFactorList(t *testing.T) {
	mock := richMock()
	mock.orgSecurity.DefaultRepositoryPermission = "admin"
	mock.membership.TwoFADisabled = nil
	mock.membership.TwoFAErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, github.ErrPermissionDenied)
	a, gaps := accessAt(t, componentsdk.LevelTrust, mock)
	wantFlag(t, "local_admins_present", a.Admins.LocalAdminsPresent, true)
	if a.Admins.LocalAdminMFACoveragePct.Read {
		t.Errorf("local_admin_mfa_coverage_pct = %+v, want it left out", a.Admins.LocalAdminMFACoveragePct)
	}
	if g := accessGap(gaps, "/admins/local_admin_mfa_coverage_pct"); g == nil || g.Code != componentsdk.CodePermissionDenied {
		t.Errorf("gap = %+v, want permission_denied", g)
	}
}

// Outside collaborators are not on GitHub's list of members without
// two-factor authentication. Their own list says which of them lack it,
// whatever the organization requires.
func TestAccessMembersMFAForOutsideCollaborators(t *testing.T) {
	denied := componentsdk.CodeError(componentsdk.CodePermissionDenied, github.ErrPermissionDenied)
	for _, tc := range []struct {
		name     string
		required *bool
		disabled map[string]bool
		err      error
		want     int
		pct      int
		code     componentsdk.Code
	}{
		// alice has MFA and bob does not.
		{name: "with it", required: boolPtr(true), disabled: map[string]bool{}, want: 2, pct: 66},
		{name: "without it", required: boolPtr(false), disabled: map[string]bool{"carol": true}, want: 1, pct: 33},
		{name: "requirement hidden", disabled: map[string]bool{}, want: 2, pct: 66},
		{name: "list refused", required: boolPtr(true), err: denied, code: componentsdk.CodePermissionDenied},
		{name: "list at the cap", required: boolPtr(true), code: componentsdk.CodeTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := richMock()
			mock.orgSecurity.TwoFactorRequired = tc.required
			mock.orgSecurity.DefaultRepositoryPermission = "admin"
			mock.membership.CollaboratorsTwoFADisabled, mock.membership.CollaboratorsTwoFAErr = tc.disabled, tc.err
			a, gaps := accessAt(t, componentsdk.LevelAudit, mock)
			g := accessGap(gaps, "/members/local_mfa_member_count")
			if tc.code == "" {
				if a.Members.LocalMFAMemberCount == nil || *a.Members.LocalMFAMemberCount != tc.want {
					t.Errorf("local_mfa_member_count = %v, want %d", a.Members.LocalMFAMemberCount, tc.want)
				}
				wantPct(t, "local_mfa_coverage_pct", a.Members.LocalMFACoveragePct, tc.pct)
				return
			}
			if a.Members.LocalMFAMemberCount != nil || a.Members.LocalMFACoveragePct.Read {
				t.Errorf("members = %+v, want the MFA values left out", a.Members)
			}
			if g == nil || g.Code != tc.code || g.Status != componentsdk.GapPartial || g.Unmeasured != 1 {
				t.Errorf("gap = %+v, want a partial %s gap with the 1 outside collaborator unmeasured", g, tc.code)
			}
			// The admins are members, so their MFA stays: alice has it
			// and bob does not.
			wantPct(t, "local_admin_mfa_coverage_pct", a.Admins.LocalAdminMFACoveragePct, 50)
		})
	}
}

// With no outside collaborators, the member MFA values need only the
// members' list.
func TestAccessMembersMFAWithNoOutsideCollaborators(t *testing.T) {
	mock := richMock()
	mock.membership.OutsideCollaborators, mock.membership.CollaboratorsTwoFADisabled = nil, nil
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	if a.Members.LocalMFAMemberCount == nil || *a.Members.LocalMFAMemberCount != 1 {
		t.Errorf("local_mfa_member_count = %v, want alice alone", a.Members.LocalMFAMemberCount)
	}
	wantPct(t, "local_mfa_coverage_pct", a.Members.LocalMFACoveragePct, 50)
}

func TestAccessMembersCountOutsideCollaboratorsAsExternal(t *testing.T) {
	a, _ := accessAt(t, componentsdk.LevelAudit, richMock())
	if a.Members.MemberCount == nil || *a.Members.MemberCount != 3 || a.Members.ExternalMemberCount == nil || *a.Members.ExternalMemberCount != 1 {
		t.Errorf("members = %+v, want 3 people with 1 outside collaborator", a.Members)
	}
	if a.Members.LocalMemberCount == nil || *a.Members.LocalMemberCount != 3 {
		t.Errorf("local_member_count = %v, want every person, since each signs in with a GitHub account", a.Members.LocalMemberCount)
	}
}

// Members linked to SAML count as local too, since whether the organization
// requires SAML is not read. So local and SSO members overlap.
func TestAccessMembersLinkedToSAMLAreLocal(t *testing.T) {
	mock := richMock()
	mock.orgSecurity.DefaultRepositoryPermission = "admin"
	mock.sso = &github.OrgSSO{Configured: true, LinkedMembers: 2, NameIDs: map[string]string{"alice": "alice@idp", "bob": "bob@idp"}}
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	if a.Members.SSOMemberCount == nil || *a.Members.SSOMemberCount != 2 || a.Members.LocalMemberCount == nil || *a.Members.LocalMemberCount != 3 {
		t.Errorf("members = %+v, want 2 linked to SAML and all 3 local", a.Members)
	}
	if a.Admins.LocalAdminCount == nil || *a.Admins.LocalAdminCount != 2 {
		t.Errorf("local_admin_count = %v, want both members, who are linked to SAML", a.Admins.LocalAdminCount)
	}
}

// With the admin base permission, every member can change who has access
// to every repository, so every member is an admin. An outside
// collaborator does not get the base permission.
func TestAccessAdminsAreEveryMemberWithTheAdminBasePermission(t *testing.T) {
	mock := richMock()
	mock.orgSecurity.DefaultRepositoryPermission = "admin"
	a, gaps := accessAt(t, componentsdk.LevelAudit, mock)
	if a.Admins.AdminCount == nil || *a.Admins.AdminCount != 2 {
		t.Errorf("admin_count = %v, want alice and bob", a.Admins.AdminCount)
	}
	wantPct(t, "admin_share_pct", a.Admins.AdminSharePct, 67)
	if g := accessGap(gaps, "/admins/admin_count"); g != nil {
		t.Errorf("admin_count gap = %+v, want none", g)
	}
}

// Below the admin base permission, a member can still be an admin through
// an organization role, which the collector does not read. The admin
// values are left out with a not_read gap, and the owner still makes the
// present flags true. When GitHub withholds the base permission, the gap is
// permission_denied.
func TestAccessAdminsLeftOutWithoutOrganizationRoles(t *testing.T) {
	for _, tc := range []struct {
		base string
		code componentsdk.Code
	}{
		{"read", componentsdk.CodeNotRead},
		{"write", componentsdk.CodeNotRead},
		{"", componentsdk.CodePermissionDenied},
	} {
		mock := richMock()
		mock.orgSecurity.DefaultRepositoryPermission = tc.base
		a, gaps := accessAt(t, componentsdk.LevelAudit, mock)
		wantFlag(t, "admins_present", a.Admins.AdminsPresent, true)
		wantFlag(t, "local_admins_present", a.Admins.LocalAdminsPresent, true)
		if a.Admins.AdminCount != nil || a.Admins.AdminSharePct.Read || a.Admins.LocalMFAAdminCount != nil || a.Admins.LocalAdminMFACoveragePct.Read {
			t.Errorf("base %q: admins = %+v, want the counts and percentages left out", tc.base, a.Admins)
		}
		for _, pointer := range []string{"/admins/admin_count", "/admins/admin_share_pct", "/admins/local_admin_count", "/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct"} {
			if g := accessGap(gaps, pointer); g == nil || g.Code != tc.code {
				t.Errorf("base %q: %s gap = %+v, want %s", tc.base, pointer, g, tc.code)
			}
		}
		if g := accessGap(gaps, "/admins/admin_count"); tc.code == componentsdk.CodeNotRead && (g == nil || !strings.Contains(g.Detail, "Custom organization roles")) {
			t.Errorf("base %q: admin_count gap = %+v, want it to name the permission", tc.base, g)
		}
	}
}

// The fourth App access check has no GitHub data: the API does not report
// when a member last signed in.
func TestAccessInactiveMembersAreUnsupported(t *testing.T) {
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		_, gaps := accessAt(t, level, richMock())
		if g := accessGap(gaps, "/members/inactive_pct"); g == nil || g.Code != componentsdk.CodeUnsupported {
			t.Errorf("%s: inactive_pct gap = %+v, want unsupported", level, g)
		}
		count := accessGap(gaps, "/members/inactive_member_count")
		if level == componentsdk.LevelTrust && count != nil {
			t.Errorf("trust: a gap on inactive_member_count, which a trust run does not write")
		}
		if level == componentsdk.LevelAudit && (count == nil || count.Code != componentsdk.CodeUnsupported) {
			t.Errorf("audit: inactive_member_count gap = %+v, want unsupported", count)
		}
	}
}

// A GitHub organization has no built-in root account, so the root flags
// are false at every level and no root value has a gap.
func TestAccessHasNoRootAccounts(t *testing.T) {
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		a, gaps := accessAt(t, level, richMock())
		wantFlag(t, "root_accounts_present", a.Root.RootAccountsPresent, false)
		wantFlag(t, "root_access_keys_present", a.Root.RootAccessKeysPresent, false)
		wantNull(t, "root_mfa_coverage_pct", a.Root.RootMFACoveragePct)
		for _, g := range gaps {
			if g.Path == AccessPath && strings.HasPrefix(g.Pointer, "/root") {
				t.Errorf("%s: a %s gap at %s", level, g.Code, g.Pointer)
			}
		}
		counts := []*int{a.Root.RootAccountCount, a.Root.RootMFAAccountCount}
		for _, n := range counts {
			switch {
			case level == componentsdk.LevelTrust && n != nil:
				t.Errorf("trust: a root count of %d, which a trust run does not write", *n)
			case level == componentsdk.LevelAudit && (n == nil || *n != 0):
				t.Errorf("audit: root counts %v and %v, want 0", a.Root.RootAccountCount, a.Root.RootMFAAccountCount)
			}
		}
	}
}

func TestAccessMembersLeftOutWhenTheMemberListFails(t *testing.T) {
	mock := richMock()
	mock.membershipErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, github.ErrPermissionDenied)
	a, gaps := accessAt(t, componentsdk.LevelTrust, mock)
	if a.Members.MembersPresent != nil || a.Admins.AdminsPresent != nil || a.Admins.LocalAdminMFACoveragePct.Read {
		t.Errorf("members %+v and admins %+v, want them left out", a.Members, a.Admins)
	}
	for _, pointer := range []string{"/members/members_present", "/admins/admins_present", "/admins/local_admin_mfa_coverage_pct"} {
		if g := accessGap(gaps, pointer); g == nil || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("%s gap = %+v, want permission_denied", pointer, g)
		}
	}
}

// The third App access check: credentials that never expire. Deploy keys
// never expire, and a fine-grained token with no expiry date does not.
func TestAccessCredentialsNeverExpiring(t *testing.T) {
	mock := richMock()
	mock.pats = []github.PATGrant{
		{ID: 1, Permissions: []string{"contents:read"}, ExpiresAt: "2026-12-01T00:00:00Z", LastUsed: "2026-10-01T00:00:00Z"},
		{ID: 2, Permissions: []string{"contents:write"}},
		{ID: 3, Permissions: []string{"administration:admin"}, ExpiresAt: "2027-01-01T00:00:00Z", LastUsed: "2026-07-18T00:00:00Z"},
	}
	mock.deployKeys = map[string][]github.DeployKey{
		"test-org/repo1": {{ID: 4, ReadOnly: true, LastUsed: "2026-10-16T00:00:00Z"}},
		"test-org/repo2": {{ID: 5, ReadOnly: false}},
	}
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	c := a.Credentials
	wantFlag(t, "credentials_present", c.CredentialsPresent, true)
	for name, got := range map[string]struct {
		count *int
		want  int
	}{
		"credential_count":                {c.CredentialCount, 5},
		"never_expiring_credential_count": {c.NeverExpiringCredentialCount, 3}, // grant 2 and both keys
		"unused_credential_count":         {c.UnusedCredentialCount, 3},        // grant 2, grant 3 at 91 days, and key 5
		"write_access_credential_count":   {c.WriteAccessCredentialCount, 3},   // grants 2 and 3, and key 5
	} {
		if got.count == nil || *got.count != got.want {
			t.Errorf("%s = %v, want %d", name, got.count, got.want)
		}
	}
	wantPct(t, "never_expiring_pct", c.NeverExpiringPct, 60)
	wantPct(t, "unused_pct", c.UnusedPct, 60)
	wantPct(t, "write_access_pct", c.WriteAccessPct, 60)
}

// A token that expired and a deploy key GitHub disabled can't be used, so
// neither counts.
func TestAccessCredentialsLeaveOutExpiredTokensAndDisabledKeys(t *testing.T) {
	mock := richMock()
	mock.pats = []github.PATGrant{{ID: 1, ExpiresAt: "2026-12-01T00:00:00Z"}, {ID: 2, ExpiresAt: "2026-09-01T00:00:00Z", Expired: true}}
	mock.deployKeys = map[string][]github.DeployKey{"test-org/repo1": {{ID: 3, ReadOnly: true, CreatedAt: "2026-10-01T00:00:00Z"}, {ID: 4, Disabled: true}}}
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	if c := a.Credentials.CredentialCount; c == nil || *c != 2 {
		t.Errorf("credential_count = %v, want 2: grant 1 and key 3", c)
	}
	wantPct(t, "never_expiring_pct", a.Credentials.NeverExpiringPct, 50)

	mock = richMock()
	mock.pats = []github.PATGrant{{ID: 2, Expired: true}}
	mock.deployKeys = map[string][]github.DeployKey{"test-org/repo1": {{ID: 4, Disabled: true}}}
	a, _ = accessAt(t, componentsdk.LevelTrust, mock)
	wantFlag(t, "credentials_present", a.Credentials.CredentialsPresent, false)
	wantNull(t, "never_expiring_pct", a.Credentials.NeverExpiringPct)
}

func TestAccessCredentialsWithNoneAreNull(t *testing.T) {
	mock := richMock()
	mock.pats, mock.deployKeys = nil, nil
	a, _ := accessAt(t, componentsdk.LevelTrust, mock)
	wantFlag(t, "credentials_present", a.Credentials.CredentialsPresent, false)
	wantNull(t, "never_expiring_pct", a.Credentials.NeverExpiringPct)
	wantNull(t, "unrestricted_pct", a.Credentials.UnrestrictedPct)
	wantNull(t, "rotation_overdue_pct", a.Credentials.RotationOverduePct)
}

// A fine-grained token has only the permissions and repositories it was
// given, and a deploy key works on one repository, so none is unrestricted.
func TestAccessCredentialsAreNeverUnrestricted(t *testing.T) {
	mock := richMock()
	mock.pats = []github.PATGrant{{ID: 1, Permissions: []string{"administration:admin", "contents:write"}}}
	a, gaps := accessAt(t, componentsdk.LevelAudit, mock)
	if c := a.Credentials.UnrestrictedCredentialCount; c == nil || *c != 0 {
		t.Errorf("unrestricted_credential_count = %v, want 0", c)
	}
	wantPct(t, "unrestricted_pct", a.Credentials.UnrestrictedPct, 0)
	if g := accessGap(gaps, "/credentials/unrestricted_pct"); g != nil {
		t.Errorf("unrestricted_pct gap = %+v, want none", g)
	}
}

// Rotation counts the deploy keys created more than 90 days ago. A token
// grant has no creation date, so any grant leaves the values out.
func TestAccessCredentialsRotationOverdue(t *testing.T) {
	keys := map[string][]github.DeployKey{
		"test-org/repo1": {{ID: 4, ReadOnly: true, CreatedAt: "2026-07-19T11:59:59Z"}}, // just over 90 days
		"test-org/repo2": {{ID: 5, ReadOnly: false, CreatedAt: "2026-07-19T12:00:00Z"}},
	}
	mock := richMock()
	mock.pats, mock.deployKeys = nil, keys
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	if c := a.Credentials.RotationOverdueCredentialCount; c == nil || *c != 1 {
		t.Errorf("rotation_overdue_credential_count = %v, want 1", c)
	}
	wantPct(t, "rotation_overdue_pct", a.Credentials.RotationOverduePct, 50)

	mock = richMock()
	mock.pats, mock.deployKeys = []github.PATGrant{{ID: 1}, {ID: 2}}, keys
	a, gaps := accessAt(t, componentsdk.LevelTrust, mock)
	if a.Credentials.RotationOverduePct.Read {
		t.Errorf("rotation_overdue_pct = %+v, want it left out", a.Credentials.RotationOverduePct)
	}
	g := accessGap(gaps, "/credentials/rotation_overdue_pct")
	if g == nil || g.Code != componentsdk.CodeUnsupported || g.Status != componentsdk.GapPartial || g.Unmeasured != 2 {
		t.Errorf("rotation_overdue_pct gap = %+v, want a partial unsupported gap with the 2 grants unmeasured", g)
	}

	mock = richMock()
	mock.pats, mock.deployKeys = nil, map[string][]github.DeployKey{"test-org/repo1": {{ID: 4}}}
	_, gaps = accessAt(t, componentsdk.LevelTrust, mock)
	if g := accessGap(gaps, "/credentials/rotation_overdue_pct"); g == nil || g.Code != componentsdk.CodeInvalidResponse {
		t.Errorf("rotation_overdue_pct gap = %+v, want invalid_response for a key with no creation date", g)
	}
}

// A missing fine-grained token policy is not_licensed and leaves the
// credential values out without failing the run. A deploy key still shows
// that credentials are present.
func TestAccessCredentialsWithoutTheTokenList(t *testing.T) {
	mock := richMock()
	mock.patsErr = componentsdk.CodeError(componentsdk.CodeNotLicensed, github.ErrFeatureUnavailable)
	a, gaps := accessAt(t, componentsdk.LevelTrust, mock)
	wantFlag(t, "credentials_present", a.Credentials.CredentialsPresent, true)
	if a.Credentials.NeverExpiringPct.Read {
		t.Errorf("never_expiring_pct = %+v, want it left out", a.Credentials.NeverExpiringPct)
	}
	if g := accessGap(gaps, "/credentials/never_expiring_pct"); g == nil || g.Code != componentsdk.CodeNotLicensed {
		t.Errorf("gap = %+v, want not_licensed", g)
	}
}

func TestUnusedSince(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for lastUsed, want := range map[string]bool{
		"":                     true,
		"2026-07-19T12:00:00Z": false, // 90 days
		"2026-07-19T11:59:59Z": true,
		"2026-10-16T00:00:00Z": false,
	} {
		got, err := unusedSince(lastUsed, now)
		if err != nil || got != want {
			t.Errorf("unusedSince(%q) = %t with error %v, want %t", lastUsed, got, err, want)
		}
	}
	if _, err := unusedSince("yesterday", now); !errors.Is(err, errBadTimestamp) {
		t.Errorf("an unreadable time gave %v, want errBadTimestamp", err)
	}
}

func TestGrantsWrite(t *testing.T) {
	for perms, want := range map[string]bool{
		"contents:read":                     false,
		"contents:read,pull_requests:write": true,
		"administration:admin":              true,
		"":                                  false,
	} {
		var list []string
		if perms != "" {
			list = strings.Split(perms, ",")
		}
		if got := grantsWrite(list); got != want {
			t.Errorf("grantsWrite(%q) = %t, want %t", perms, got, want)
		}
	}
}

// A suspended App cannot reach the organization's resources, so it does not
// count as a connected app.
func TestAccessConnectedAppsSkipSuspendedInstallations(t *testing.T) {
	mock := richMock()
	mock.installations = []github.Installation{
		{AppSlug: "dependabot", AppID: 99},
		{AppSlug: "renovate", AppID: 100, Suspended: true},
	}
	a, _ := accessAt(t, componentsdk.LevelAudit, mock)
	wantFlag(t, "apps_present", a.ConnectedApps.AppsPresent, true)
	if got := a.ConnectedApps.AppCount; got == nil || *got != 1 {
		t.Errorf("app_count = %v, want 1 for the installation that is not suspended", got)
	}

	mock = richMock()
	mock.installations = []github.Installation{{AppSlug: "renovate", AppID: 100, Suspended: true}}
	a, _ = accessAt(t, componentsdk.LevelTrust, mock)
	wantFlag(t, "apps_present", a.ConnectedApps.AppsPresent, false)
}

// The installations past the end of a list cut short of GitHub's total may
// be suspended, so the count is left out.
func TestAccessConnectedAppsLeaveOutACutList(t *testing.T) {
	mock := richMock()
	mock.installationTotal = 3
	a, gaps := accessAt(t, componentsdk.LevelAudit, mock)
	wantFlag(t, "apps_present", a.ConnectedApps.AppsPresent, true)
	if a.ConnectedApps.AppCount != nil {
		t.Errorf("app_count = %d, want it left out", *a.ConnectedApps.AppCount)
	}
	if g := accessGap(gaps, "/connected_apps/app_count"); g == nil || g.Code != componentsdk.CodeTooLarge {
		t.Errorf("app_count gap = %+v, want too_large", g)
	}
}

// A trust run reads only the rosters, without the names and invitations
// that the detailed artifact holds.
func TestTrustRunReadsTheRostersOnly(t *testing.T) {
	mock := richMock()
	accessAt(t, componentsdk.LevelTrust, mock)
	if len(mock.membershipReads) != 1 || mock.membershipReads[0] != "rosters" {
		t.Errorf("membership reads = %v, want one rosters read", mock.membershipReads)
	}
	mock = richMock()
	accessAt(t, componentsdk.LevelAudit, mock)
	if len(mock.membershipReads) != 1 || mock.membershipReads[0] != "membership" {
		t.Errorf("membership reads = %v, want one full read shared by both artifacts", mock.membershipReads)
	}
}

// A trust run that collects neither new artifact makes none of their calls.
func TestTrustRunWithoutTheNewArtifactsReadsNoRosters(t *testing.T) {
	mock := richMock()
	c := NewWithClient(Config{Organization: "test-org", IncludePatterns: []string{"*"}}, mock)
	posture, err := c.Collect(t.Context(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if len(mock.membershipReads) != 0 || posture.access != nil || posture.vulns != nil {
		t.Errorf("membership reads %v, access %v, and vulns %v, want none", mock.membershipReads, posture.access, posture.vulns)
	}
}
