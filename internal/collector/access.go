package collector

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// AccessPosture is the normalized evidencepack/access-posture@v1 artifact
// for the organization. A value the run could not read is left out with a
// gap, and a percentage over no one is null. The counts are written from the
// audit level, and the present flags at every level.
type AccessPosture struct {
	SchemaVersion string              `json:"schema_version"`
	CollectedAt   string              `json:"collected_at"`
	Provider      string              `json:"provider"`
	SystemType    string              `json:"system_type"`
	SignIn        AccessSignIn        `json:"sign_in,omitzero"`
	Members       AccessMembers       `json:"members,omitzero"`
	Admins        AccessAdmins        `json:"admins,omitzero"`
	Credentials   AccessCredentials   `json:"credentials,omitzero"`
	ConnectedApps AccessConnectedApps `json:"connected_apps,omitzero"`
}

// AccessSignIn is how people sign in to the organization. sso_required is
// always left out, since GitHub reports it only to enterprise owners.
type AccessSignIn struct {
	SSOConfigured *bool `json:"sso_configured,omitempty"`
	MFARequired   *bool `json:"mfa_required,omitempty"`
	SCIMEnabled   *bool `json:"scim_enabled,omitempty"`
}

// AccessMembers is the organization's members and outside collaborators.
// The inactive values are always left out, since when a member last signed
// in is not available from GitHub's API. Every member counts as able to sign
// in without SSO, since the run does not read whether the organization
// requires SAML single sign-on.
type AccessMembers struct {
	MembersPresent         *bool        `json:"members_present,omitempty"`
	MemberCount            *int         `json:"member_count,omitempty"`
	ExternalMembersPresent *bool        `json:"external_members_present,omitempty"`
	ExternalMemberCount    *int         `json:"external_member_count,omitempty"`
	SSOMemberCount         *int         `json:"sso_member_count,omitempty"`
	SSOCoveragePct         Reading[int] `json:"sso_coverage_pct,omitzero"`
	LocalMembersPresent    *bool        `json:"local_members_present,omitempty"`
	LocalMemberCount       *int         `json:"local_member_count,omitempty"`
	LocalMFAMemberCount    *int         `json:"local_mfa_member_count,omitempty"`
	LocalMFACoveragePct    Reading[int] `json:"local_mfa_coverage_pct,omitzero"`
}

// AccessAdmins is the organization's owners.
type AccessAdmins struct {
	AdminsPresent            *bool        `json:"admins_present,omitempty"`
	AdminCount               *int         `json:"admin_count,omitempty"`
	AdminSharePct            Reading[int] `json:"admin_share_pct,omitzero"`
	LocalAdminsPresent       *bool        `json:"local_admins_present,omitempty"`
	LocalAdminCount          *int         `json:"local_admin_count,omitempty"`
	LocalMFAAdminCount       *int         `json:"local_mfa_admin_count,omitempty"`
	LocalAdminMFACoveragePct Reading[int] `json:"local_admin_mfa_coverage_pct,omitzero"`
}

// AccessCredentials is the fine-grained personal access tokens approved for
// the organization and the deploy keys of the in-scope repositories.
// Neither kind is unrestricted. The rotation values cover the deploy keys
// alone, since a token grant has no creation date. They are left out when
// there is a grant.
type AccessCredentials struct {
	CredentialsPresent             *bool        `json:"credentials_present,omitempty"`
	CredentialCount                *int         `json:"credential_count,omitempty"`
	NeverExpiringCredentialCount   *int         `json:"never_expiring_credential_count,omitempty"`
	NeverExpiringPct               Reading[int] `json:"never_expiring_pct,omitzero"`
	UnusedCredentialCount          *int         `json:"unused_credential_count,omitempty"`
	UnusedPct                      Reading[int] `json:"unused_pct,omitzero"`
	UnrestrictedCredentialCount    *int         `json:"unrestricted_credential_count,omitempty"`
	UnrestrictedPct                Reading[int] `json:"unrestricted_pct,omitzero"`
	WriteAccessCredentialCount     *int         `json:"write_access_credential_count,omitempty"`
	WriteAccessPct                 Reading[int] `json:"write_access_pct,omitzero"`
	RotationOverdueCredentialCount *int         `json:"rotation_overdue_credential_count,omitempty"`
	RotationOverduePct             Reading[int] `json:"rotation_overdue_pct,omitzero"`
}

// AccessConnectedApps is the GitHub Apps installed on the organization that
// are not suspended.
type AccessConnectedApps struct {
	AppsPresent *bool `json:"apps_present,omitempty"`
	AppCount    *int  `json:"app_count,omitempty"`
}

// UnusedDays is how long a credential can go unused before it counts as
// unused, and RotationDays how old one can be before its rotation is
// overdue, as the access-posture schema sets them.
const (
	UnusedDays   = 90
	RotationDays = 90
)

// Reasons a value of the normalized artifacts is left out. Each list that
// reaches its read cap may hold more than was read.
var (
	errMembersCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d members were read", github.MemberFetchCap))
	errCollaboratorsCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d outside collaborators were read", github.MemberFetchCap))
	errOwnersCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d owners were read", github.MemberFetchCap))
	errTwoFactorListCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d members without two-factor authentication were read", github.MemberFetchCap))
	errCollaboratorTwoFactorListCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d outside collaborators without two-factor authentication were read", github.MemberFetchCap))
	errIdentitiesCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d SAML identities were read", github.IdentityFetchCap))
	errGrantsCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d fine-grained token grants were read", github.TokenGrantFetchCap))
	errDeployKeysCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("a repository has more than %d deploy keys, and only the first %d were read", github.DeployKeyFetchCap, github.DeployKeyFetchCap))
	errInstallationsCut = componentsdk.CodeError(componentsdk.CodeTooLarge,
		fmt.Errorf("only the first %d GitHub App installations were read", github.InventoryFetchCap))
	// errGrantCreationUnreported is why the rotation values are left out
	// when the organization has approved a fine-grained token.
	errGrantCreationUnreported = componentsdk.CodeError(componentsdk.CodeUnsupported,
		errors.New("GitHub's list of fine-grained token grants has no creation date"))
	errCountsDisagree = componentsdk.CodeError(componentsdk.CodeInvalidResponse,
		errors.New("one GitHub list has more people than the list it is a share of"))
	errBadTimestamp = componentsdk.CodeError(componentsdk.CodeInvalidResponse,
		errors.New("a timestamp from GitHub is not in RFC 3339 format"))
	// errNotRead is a list the run never read, which is a bug in the
	// collector. It keeps an unread list from counting as empty.
	errNotRead = componentsdk.CodeError(componentsdk.CodeInternal, errors.New("the list was not read"))
)

// ssoRequiredNotRead is the detail of the gap at /sign_in/sso_required. A
// run of 40 or more letters in a gap's detail is scrubbed as a possible
// secret, and the GraphQL field's name is that long. So the detail names the
// object that holds the field.
const ssoRequiredNotRead = "Only enterprise owners can read whether an organization requires SAML single sign-on, " +
	"from the GraphQL EnterpriseOwnerInfo object. This value is not collected."

// measure is a value the run read, or the error that kept it from being
// read. unmeasured counts the items a rollup could not read, and is 0 for a
// value left out whole.
type measure[T any] struct {
	value      T
	err        error
	unmeasured int
}

func known[T any](v T) measure[T] { return measure[T]{value: v} }

func unknown[T any](err error, unmeasured int) measure[T] {
	return measure[T]{err: err, unmeasured: unmeasured}
}

// unknownAs returns m's failure as a measure of another type.
func unknownAs[T, U any](m measure[U]) measure[T] { return unknown[T](m.err, m.unmeasured) }

// sum adds two counts. It fails with the first one that failed.
func sum(a, b measure[int]) measure[int] {
	switch {
	case a.err != nil:
		return a
	case b.err != nil:
		return b
	}
	return known(a.value + b.value)
}

// anyAbove is true when have is, and otherwise whether total is above 0. It
// fails with total's failure when have is false and total could not be
// read.
func anyAbove(have bool, total measure[int]) measure[bool] {
	switch {
	case have:
		return known(true)
	case total.err != nil:
		return unknownAs[bool](total)
	}
	return known(total.value > 0)
}

// writer writes the values of one normalized artifact and records a gap for
// each value it leaves out. audit is true from the audit level, where the
// counts are written.
type writer struct {
	gaps  *gapLog
	path  string
	audit bool
}

// flag returns m's value, or nil with a gap at pointer.
func (w writer) flag(pointer string, m measure[bool]) *bool {
	w.gaps.rec.Helper()
	if m.err != nil {
		w.gaps.leaveOutOf(w.path, m.err, m.unmeasured, pointer)
		return nil
	}
	return ptr(m.value)
}

// count returns m's value from the audit level, or nil with a gap at
// pointer. Below the audit level it returns nil with no gap, since the
// schema leaves counts out there.
func (w writer) count(pointer string, m measure[int]) *int {
	w.gaps.rec.Helper()
	if !w.audit {
		return nil
	}
	if m.err != nil {
		w.gaps.leaveOutOf(w.path, m.err, m.unmeasured, pointer)
		return nil
	}
	return ptr(m.value)
}

// pct returns num as a whole percentage of den, rounded as rounding says. It
// is null when den is 0, and left out with a gap at pointer when either
// count could not be read.
func (w writer) pct(pointer string, num, den measure[int], rounding componentsdk.Rounding) Reading[int] {
	w.gaps.rec.Helper()
	var err error
	unmeasured := 0
	switch {
	case den.err != nil:
		err, unmeasured = den.err, den.unmeasured
	case den.value == 0:
		return Reading[int]{Read: true}
	case num.err != nil:
		err, unmeasured = num.err, num.unmeasured
	case num.value > den.value:
		err = errCountsDisagree
	default:
		return Reading[int]{Value: componentsdk.Percent(num.value, den.value, rounding), Read: true}
	}
	w.gaps.leaveOutOf(w.path, err, unmeasured, pointer)
	return Reading[int]{}
}

// auditOnly returns pointers when w writes counts, and none otherwise, so a
// gap is recorded only on a value the run writes.
func (w writer) auditOnly(pointers ...string) []string {
	if !w.audit {
		return nil
	}
	return pointers
}

// people is the organization's members, outside collaborators, and owners,
// as the access-posture artifact counts them.
type people struct {
	members, external, localMFA     measure[int]
	membersPresent, externalPresent measure[bool]
	admins, adminMFA                measure[int]
	adminsPresent                   measure[bool]
	ssoMembers                      measure[int]
	ssoConfigured, scimEnabled      measure[bool]
}

// countPeople counts the people in ms, read with err.
func countPeople(ms *github.OrgMembership, err error) people {
	var p people
	if err != nil {
		p.members, p.external, p.localMFA, p.admins, p.adminMFA = unknown[int](err, 0), unknown[int](err, 0), unknown[int](err, 0), unknown[int](err, 0), unknown[int](err, 0)
		p.membersPresent, p.externalPresent, p.adminsPresent = unknown[bool](err, 0), unknown[bool](err, 0), unknown[bool](err, 0)
		return p
	}
	memberSet := toSet(ms.Members)
	outsideSet := map[string]bool{}
	for _, login := range ms.OutsideCollaborators {
		if !memberSet[login] {
			outsideSet[login] = true
		}
	}
	adminSet := toSet(ms.Admins)

	orgMembers := known(len(memberSet))
	if ms.MembersMore {
		orgMembers = unknown[int](errMembersCut, 0)
	}
	switch {
	case ms.OutsideCollaboratorsErr != nil:
		p.external = unknown[int](ms.OutsideCollaboratorsErr, 0)
		p.externalPresent = unknown[bool](ms.OutsideCollaboratorsErr, 0)
	case ms.OutsideCollaboratorsMore:
		p.external = unknown[int](errCollaboratorsCut, 0)
		p.externalPresent = known(true)
	default:
		p.external = known(len(outsideSet))
		p.externalPresent = known(len(outsideSet) > 0)
	}
	p.members = sum(orgMembers, p.external)
	p.membersPresent = anyAbove(len(memberSet) > 0 || len(outsideSet) > 0, p.members)

	switch {
	case ms.AdminsErr != nil:
		p.admins = unknown[int](ms.AdminsErr, 0)
	case ms.AdminsMore:
		p.admins = unknown[int](errOwnersCut, 0)
	default:
		p.admins = known(len(adminSet))
	}
	p.adminsPresent = anyAbove(ms.AdminsErr == nil && len(adminSet) > 0, p.admins)

	// GitHub lists the members without two-factor authentication and the
	// outside collaborators without it separately.
	roster := func(disabled map[string]bool, err, cut error) measure[map[string]bool] {
		switch {
		case err != nil:
			return unknown[map[string]bool](err, 0)
		case disabled == nil:
			return unknown[map[string]bool](cut, 0)
		}
		return known(disabled)
	}
	withMFA := func(logins map[string]bool, total measure[int], twoFactor measure[map[string]bool]) measure[int] {
		switch {
		case total.err != nil:
			return total
		case total.value == 0:
			return known(0)
		case twoFactor.err != nil:
			return unknownAs[int](twoFactor)
		}
		n := 0
		for login := range logins {
			if !twoFactor.value[login] {
				n++
			}
		}
		return known(n)
	}
	memberTwoFactor := roster(ms.TwoFADisabled, ms.TwoFAErr, errTwoFactorListCut)
	p.adminMFA = withMFA(adminSet, p.admins, memberTwoFactor)
	// The members' count stays readable when only the outside collaborators'
	// list fails, so the total is then partial.
	outsideMFA := withMFA(outsideSet, p.external, roster(ms.CollaboratorsTwoFADisabled, ms.CollaboratorsTwoFAErr, errCollaboratorTwoFactorListCut))
	if outsideMFA.err != nil && p.external.err == nil {
		outsideMFA.unmeasured = p.external.value
	}
	p.localMFA = sum(withMFA(memberSet, orgMembers, memberTwoFactor), outsideMFA)
	return p
}

// addSSO counts the people sso shows signing in through SAML single
// sign-on, read with err.
func (p *people) addSSO(sso *github.OrgSSO, err error) {
	switch {
	case err != nil:
		p.ssoConfigured, p.scimEnabled, p.ssoMembers = unknown[bool](err, 0), unknown[bool](err, 0), unknown[int](err, 0)
		return
	case sso == nil:
		sso = &github.OrgSSO{}
	}
	p.ssoConfigured = known(sso.Configured)
	p.ssoMembers = known(sso.LinkedMembers)
	p.scimEnabled = known(sso.SCIMMembers > 0)
	if sso.More {
		p.ssoMembers = unknown[int](errIdentitiesCut, 0)
		if sso.SCIMMembers == 0 {
			p.scimEnabled = unknown[bool](errIdentitiesCut, 0)
		}
	}
}

// toAccessPosture builds the access-posture artifact from the organization's
// two-factor requirement in sec and the lists the run read.
func (c *Collector) toAccessPosture(posture *OrgPosture, sec *github.OrgSecurity, m *metricsAggregator) *AccessPosture {
	w := writer{gaps: c.gaps, path: AccessPath, audit: c.gaps.level.AtLeast(componentsdk.LevelAudit)}
	a := &AccessPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   posture.CollectedAt,
		Provider:      "github",
		SystemType:    "code_host",
	}
	l := &m.lists
	p := countPeople(l.membership, readErr(l.membershipRead, l.membershipErr))
	p.addSSO(l.sso, readErr(l.ssoRead, l.ssoErr))

	a.SignIn = AccessSignIn{
		SSOConfigured: w.flag("/sign_in/sso_configured", p.ssoConfigured),
		// A gap on the detailed value is copied with Recorder.Mirror.
		MFARequired: sec.TwoFactorRequired,
		SCIMEnabled: w.flag("/sign_in/scim_enabled", p.scimEnabled),
	}
	w.gaps.notRead(AccessPath, ssoRequiredNotRead, "/sign_in/sso_required")

	// Every member and outside collaborator has a GitHub account they can
	// sign in to without SSO. Whether the organization requires SAML single
	// sign-on for its resources is not read. So they all count as local,
	// including the members linked to SAML.
	a.Members = AccessMembers{
		MembersPresent:         w.flag("/members/members_present", p.membersPresent),
		MemberCount:            w.count("/members/member_count", p.members),
		ExternalMembersPresent: w.flag("/members/external_members_present", p.externalPresent),
		ExternalMemberCount:    w.count("/members/external_member_count", p.external),
		SSOMemberCount:         w.count("/members/sso_member_count", p.ssoMembers),
		SSOCoveragePct:         w.pct("/members/sso_coverage_pct", p.ssoMembers, p.members, componentsdk.RoundDown),
		LocalMembersPresent:    w.flag("/members/local_members_present", p.membersPresent),
		LocalMemberCount:       w.count("/members/local_member_count", p.members),
		LocalMFAMemberCount:    w.count("/members/local_mfa_member_count", p.localMFA),
		LocalMFACoveragePct:    w.pct("/members/local_mfa_coverage_pct", p.localMFA, p.members, componentsdk.RoundDown),
	}
	w.gaps.unsupported(AccessPath, "When each member last signed in is not available from GitHub's API.",
		append(w.auditOnly("/members/inactive_member_count"), "/members/inactive_pct")...)

	a.Admins = AccessAdmins{
		AdminsPresent:            w.flag("/admins/admins_present", p.adminsPresent),
		AdminCount:               w.count("/admins/admin_count", p.admins),
		AdminSharePct:            w.pct("/admins/admin_share_pct", p.admins, p.members, componentsdk.RoundUp),
		LocalAdminsPresent:       w.flag("/admins/local_admins_present", p.adminsPresent),
		LocalAdminCount:          w.count("/admins/local_admin_count", p.admins),
		LocalMFAAdminCount:       w.count("/admins/local_mfa_admin_count", p.adminMFA),
		LocalAdminMFACoveragePct: w.pct("/admins/local_admin_mfa_coverage_pct", p.adminMFA, p.admins, componentsdk.RoundDown),
	}
	w.gaps.unsupported(AccessPath, "A GitHub organization has no root account.", "/root")

	a.Credentials = c.accessCredentials(w, m)

	haveApps, apps := activeInstallations(l.installs, l.installTotal)
	if err := readErr(l.installsRead, l.installsErr); err != nil {
		haveApps, apps = false, unknown[int](err, 0)
	}
	a.ConnectedApps = AccessConnectedApps{
		AppsPresent: w.flag("/connected_apps/apps_present", anyAbove(haveApps, apps)),
		AppCount:    w.count("/connected_apps/app_count", apps),
	}
	return a
}

// activeInstallations counts the GitHub App installations that are not
// suspended, since a suspended App cannot reach the organization's
// resources. have is true when the list holds any of them. The count is
// left out when the list stopped short of GitHub's total.
func activeInstallations(installs []github.Installation, total int) (have bool, count measure[int]) {
	n := 0
	for _, i := range installs {
		if !i.Suspended {
			n++
		}
	}
	if total > len(installs) {
		return n > 0, unknown[int](errInstallationsCut, 0)
	}
	return n > 0, known(n)
}

// accessCredentials counts the fine-grained personal access tokens approved
// for the organization and the deploy keys of the in-scope repositories.
func (c *Collector) accessCredentials(w writer, m *metricsAggregator) AccessCredentials {
	l := &m.lists
	grants := known(l.grants)
	switch err := readErr(l.grantsRead, l.grantsErr); {
	case err != nil:
		grants = unknown[[]github.PATGrant](err, 0)
	case l.grantsMore:
		grants = unknown[[]github.PATGrant](errGrantsCut, 0)
	}
	keys := known(l.keys.keys)
	switch {
	case m.reposErr != nil:
		keys = unknown[[]github.DeployKey](m.reposErr, 0)
	case !l.keysRead:
		keys = unknown[[]github.DeployKey](errNotRead, 0)
	case l.keys.failed.count > 0:
		keys = unknown[[]github.DeployKey](l.keys.failed.err, l.keys.failed.count)
	case l.keys.truncated:
		keys = unknown[[]github.DeployKey](errDeployKeysCut, 0)
	}
	now := c.now()
	// tally counts the grants and keys for which grant and key are true. A
	// failure of either fails the count.
	tally := func(grant func(github.PATGrant) (bool, error), key func(github.DeployKey) (bool, error)) measure[int] {
		switch {
		case grants.err != nil:
			return unknownAs[int](grants)
		case keys.err != nil:
			return unknownAs[int](keys)
		}
		n := 0
		for _, g := range grants.value {
			ok, err := grant(g)
			if err != nil {
				return unknown[int](err, 0)
			}
			if ok {
				n++
			}
		}
		for _, k := range keys.value {
			ok, err := key(k)
			if err != nil {
				return unknown[int](err, 0)
			}
			if ok {
				n++
			}
		}
		return known(n)
	}
	always := func(github.DeployKey) (bool, error) { return true, nil }
	total := tally(func(github.PATGrant) (bool, error) { return true, nil }, always)
	neverExpiring := tally(func(g github.PATGrant) (bool, error) { return g.ExpiresAt == "", nil }, always)
	unused := tally(
		func(g github.PATGrant) (bool, error) { return unusedSince(g.LastUsed, now) },
		func(k github.DeployKey) (bool, error) { return unusedSince(k.LastUsed, now) },
	)
	writeAccess := tally(
		func(g github.PATGrant) (bool, error) { return grantsWrite(g.Permissions), nil },
		func(k github.DeployKey) (bool, error) { return !k.ReadOnly, nil },
	)
	// A fine-grained token has only the permissions and repositories it was
	// given, and a deploy key works on one repository. So each has a scope
	// narrower than full access.
	never := func(github.PATGrant) (bool, error) { return false, nil }
	unrestricted := tally(never, func(github.DeployKey) (bool, error) { return false, nil })
	// A token grant has no creation date. So the rotation count covers the
	// deploy keys, and holds only when there is no grant.
	rotationOverdue := tally(never, func(k github.DeployKey) (bool, error) { return createdBefore(k.CreatedAt, now, RotationDays) })
	if rotationOverdue.err == nil && len(grants.value) > 0 {
		rotationOverdue = unknown[int](errGrantCreationUnreported, len(grants.value))
	}
	present := anyAbove(grants.err == nil && len(grants.value) > 0 || len(l.keys.keys) > 0, total)

	return AccessCredentials{
		CredentialsPresent:             w.flag("/credentials/credentials_present", present),
		CredentialCount:                w.count("/credentials/credential_count", total),
		NeverExpiringCredentialCount:   w.count("/credentials/never_expiring_credential_count", neverExpiring),
		NeverExpiringPct:               w.pct("/credentials/never_expiring_pct", neverExpiring, total, componentsdk.RoundUp),
		UnusedCredentialCount:          w.count("/credentials/unused_credential_count", unused),
		UnusedPct:                      w.pct("/credentials/unused_pct", unused, total, componentsdk.RoundUp),
		UnrestrictedCredentialCount:    w.count("/credentials/unrestricted_credential_count", unrestricted),
		UnrestrictedPct:                w.pct("/credentials/unrestricted_pct", unrestricted, total, componentsdk.RoundUp),
		WriteAccessCredentialCount:     w.count("/credentials/write_access_credential_count", writeAccess),
		WriteAccessPct:                 w.pct("/credentials/write_access_pct", writeAccess, total, componentsdk.RoundUp),
		RotationOverdueCredentialCount: w.count("/credentials/rotation_overdue_credential_count", rotationOverdue),
		RotationOverduePct:             w.pct("/credentials/rotation_overdue_pct", rotationOverdue, total, componentsdk.RoundUp),
	}
}

// readErr returns err for a list that was read, and errNotRead for one that
// was not.
func readErr(read bool, err error) error {
	if !read {
		return errNotRead
	}
	return err
}

// unusedSince reports whether a credential last used at lastUsed, an RFC
// 3339 time, was used more than UnusedDays before now. One never used has
// an empty lastUsed and counts as unused.
func unusedSince(lastUsed string, now time.Time) (bool, error) {
	if lastUsed == "" {
		return true, nil
	}
	t, err := time.Parse(time.RFC3339, lastUsed)
	if err != nil {
		return false, errBadTimestamp
	}
	return now.Sub(t) > UnusedDays*24*time.Hour, nil
}

// createdBefore reports whether a credential created at createdAt, an RFC
// 3339 time, was created more than days before now.
func createdBefore(createdAt string, now time.Time, days int) (bool, error) {
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return false, errBadTimestamp
	}
	return now.Sub(t) > time.Duration(days)*24*time.Hour, nil
}

// grantsWrite reports whether any of a token's permissions, each as
// name:level, is at write or admin level.
func grantsWrite(permissions []string) bool {
	for _, p := range permissions {
		if _, level, _ := strings.Cut(p, ":"); level == "write" || level == "admin" {
			return true
		}
	}
	return false
}
