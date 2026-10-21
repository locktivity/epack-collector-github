package github

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// ErrNotFound is returned when the API returns 404 Not Found. Surfaces use it
// to distinguish "absent" (a normal, expected outcome) from a real error.
var ErrNotFound = errors.New("not found")

// ErrFeatureUnavailable is returned when an endpoint requires an org feature
// the org doesn't have (e.g. Enterprise Cloud for the audit log). Surfaces
// degrade to a diagnostic rather than failing the run.
var ErrFeatureUnavailable = errors.New("feature unavailable")

// featureDisabledMarkers are substrings GitHub uses in a 403 body when a repo
// feature isn't enabled (e.g. "Advanced Security must be enabled...",
// "Dependabot alerts are disabled..."), as opposed to the App lacking the
// permission (generic "Resource not accessible by integration"). On these the
// alert surfaces degrade to a warning rather than telling the customer to grant
// a permission they may already have.
var featureDisabledMarkers = []string{
	"must be enabled",
	"not enabled",
	"is disabled",
	"are disabled",
}

func is403FeatureDisabled(body string) bool {
	lower := strings.ToLower(body)
	for _, m := range featureDisabledMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// OrgSettings holds org-level access-control settings surfaced at audit level.
// GitHub returns them only to organization owners (organization
// administration for an App), so an empty field means it was withheld.
type OrgSettings struct {
	DefaultRepositoryPermission  string
	MembersCanCreateRepositories *bool
}

// GetOrgSettings fetches org access-control settings via GET /orgs/{org}.
// Returns ErrPermissionDenied if the App lacks organization_administration:read.
//
// SSO / SCIM status is intentionally not derived here: GitHub's org REST
// endpoint does not return a reliable SSO-enabled signal, and the GraphQL
// samlIdentityProvider field has a long-standing GitHub App permission bug
// (https://github.com/orgs/community/discussions/45063). Surfacing an
// unreliable flag would be worse than omitting it.
func (c *Client) GetOrgSettings(ctx context.Context, org string) (*OrgSettings, error) {
	path := "/orgs/" + org
	var body struct {
		Login                        string `json:"login"`
		DefaultRepositoryPermission  string `json:"default_repository_permission"`
		MembersCanCreateRepositories *bool  `json:"members_can_create_repositories"`
	}
	if err := c.getJSON(ctx, "github.org_settings.get", path, &body); err != nil {
		return nil, err
	}
	if body.Login == "" {
		return nil, invalidResponse("%s response has no login", path)
	}
	return &OrgSettings{
		DefaultRepositoryPermission:  body.DefaultRepositoryPermission,
		MembersCanCreateRepositories: body.MembersCanCreateRepositories,
	}, nil
}

// AlertFetchCap bounds how many alerts of one type are listed per repo, so a
// long-neglected inventory can't blow the per-collector output limit. A list
// that reaches it comes back marked as possibly holding more.
const AlertFetchCap = 5001

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// getPagedRaw follows Link rel="next" pagination accumulating raw JSON array
// elements, stopping at maxItems. Any failure, including on a later page,
// returns an error and no items. The returned bool reports that the list
// reached maxItems, so it may hold more.
func (c *Client) getPagedRaw(ctx context.Context, op, firstPath string, maxItems int) ([]json.RawMessage, bool, error) {
	var all []json.RawMessage
	next := c.baseURL + firstPath

	for next != "" {
		resp, err := c.do(ctx, componentsdk.Operation{Name: op}, http.MethodGet, next, nil)
		if err != nil {
			return nil, false, err
		}
		var page *[]json.RawMessage
		decErr := json.NewDecoder(resp.Body).Decode(&page)
		link := resp.Header.Get("Link")
		_ = resp.Body.Close()
		if decErr != nil {
			return nil, false, componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding response: %w", trimQuery(firstPath), decErr))
		}
		if page == nil {
			return nil, false, componentsdk.ResponseError(resp, invalidResponse("%s response is not a list", trimQuery(firstPath)))
		}
		all = append(all, *page...)
		if len(all) >= maxItems {
			return all[:maxItems], true, nil
		}
		next = ""
		if m := linkNextRe.FindStringSubmatch(link); m != nil {
			next = m[1]
		}
	}
	return all, false, nil
}

// InventoryFetchCap bounds how many runners, Actions secrets, or App
// installations one list reads.
const InventoryFetchCap = 10000

// getPagedTotal follows Link rel="next" pagination over a list whose pages
// hold their items under key beside total_count, such as
// {"total_count": 2, "runners": [...]}, stopping at maxItems. It returns the
// items read and the total GitHub reports, which is larger when maxItems cut
// the list short. Any failure, including on a later page, returns an error
// and no items.
func (c *Client) getPagedTotal(ctx context.Context, op, firstPath, key string, maxItems int) ([]json.RawMessage, int, error) {
	var all []json.RawMessage
	total := 0
	next := c.baseURL + firstPath

	for next != "" {
		resp, err := c.do(ctx, componentsdk.Operation{Name: op}, http.MethodGet, next, nil)
		if err != nil {
			return nil, 0, err
		}
		var page map[string]json.RawMessage
		decErr := json.NewDecoder(resp.Body).Decode(&page)
		link := resp.Header.Get("Link")
		_ = resp.Body.Close()
		if decErr != nil {
			return nil, 0, componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding response: %w", trimQuery(firstPath), decErr))
		}
		var items []json.RawMessage
		if raw, ok := page[key]; !ok || json.Unmarshal(raw, &items) != nil || items == nil {
			return nil, 0, componentsdk.ResponseError(resp, invalidResponse("%s response has no %s list", trimQuery(firstPath), key))
		}
		var count *int
		if raw, ok := page["total_count"]; !ok || json.Unmarshal(raw, &count) != nil || count == nil {
			return nil, 0, componentsdk.ResponseError(resp, invalidResponse("%s response has no total_count", trimQuery(firstPath)))
		}
		total = *count
		all = append(all, items...)
		if len(all) >= maxItems {
			return all[:maxItems], total, nil
		}
		next = ""
		if m := linkNextRe.FindStringSubmatch(link); m != nil {
			next = m[1]
		}
	}
	return all, total, nil
}

// getAlertPages lists one alert type for a repo. A 404 means the feature is
// not enabled for the repository, so it has no alerts.
func (c *Client) getAlertPages(ctx context.Context, op, path string) ([]json.RawMessage, bool, error) {
	raw, more, err := c.getPagedRaw(ctx, op, path, AlertFetchCap)
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	return raw, more, err
}

// SecretScanningAlert is the metadata for one open secret-scanning alert.
// The secret value is never fetched or emitted.
type SecretScanningAlert struct {
	Repository string `json:"repository"`
	Number     int    `json:"number"`
	SecretType string `json:"secret_type"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at,omitempty"`
	ResolvedAt string `json:"resolved_at,omitempty"`
	ResolvedBy string `json:"resolved_by,omitempty"`
}

// CodeScanningAlert is the metadata for one open code-scanning alert.
type CodeScanningAlert struct {
	Repository      string `json:"repository"`
	Number          int    `json:"number"`
	RuleID          string `json:"rule_id"`
	Severity        string `json:"severity"`
	State           string `json:"state"`
	LocationPath    string `json:"location_path,omitempty"`
	CreatedAt       string `json:"created_at"`
	DismissedBy     string `json:"dismissed_by,omitempty"`
	DismissedReason string `json:"dismissed_reason,omitempty"`
}

// DependabotAlert is the metadata for one open Dependabot alert. No CVE
// description text is included; consumers look that up in the advisory DB.
type DependabotAlert struct {
	Repository string `json:"repository"`
	Number     int    `json:"number"`
	Package    string `json:"package"`
	Ecosystem  string `json:"ecosystem"`
	Severity   string `json:"severity"`
	CVE        string `json:"cve,omitempty"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
}

// ListSecretScanningAlerts returns open secret-scanning alerts for a repo.
func (c *Client) ListSecretScanningAlerts(ctx context.Context, owner, repo string) ([]SecretScanningAlert, bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/secret-scanning/alerts?state=open&per_page=100&hide_secret=true", owner, repo)
	raw, more, err := c.getAlertPages(ctx, "github.secret_scanning_alerts.list", path)
	if err != nil {
		return nil, false, err
	}
	out := make([]SecretScanningAlert, 0, len(raw))
	for _, r := range raw {
		var a struct {
			Number     int    `json:"number"`
			SecretType string `json:"secret_type"`
			State      string `json:"state"`
			CreatedAt  string `json:"created_at"`
			UpdatedAt  string `json:"updated_at"`
			ResolvedAt string `json:"resolved_at"`
			ResolvedBy *struct {
				Login string `json:"login"`
			} `json:"resolved_by"`
		}
		if err := json.Unmarshal(r, &a); err != nil {
			return nil, false, fmt.Errorf("%s: decoding alert: %w", trimQuery(path), err)
		}
		alert := SecretScanningAlert{
			Repository: owner + "/" + repo,
			Number:     a.Number,
			SecretType: a.SecretType,
			State:      a.State,
			CreatedAt:  a.CreatedAt,
			UpdatedAt:  a.UpdatedAt,
			ResolvedAt: a.ResolvedAt,
		}
		if a.ResolvedBy != nil {
			alert.ResolvedBy = a.ResolvedBy.Login
		}
		out = append(out, alert)
	}
	return out, more, nil
}

// ListCodeScanningAlerts returns open code-scanning alerts for a repo.
func (c *Client) ListCodeScanningAlerts(ctx context.Context, owner, repo string) ([]CodeScanningAlert, bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/code-scanning/alerts?state=open&per_page=100", owner, repo)
	raw, more, err := c.getAlertPages(ctx, "github.code_scanning_alerts.list", path)
	if err != nil {
		return nil, false, err
	}
	out := make([]CodeScanningAlert, 0, len(raw))
	for _, r := range raw {
		var a struct {
			Number int `json:"number"`
			Rule   struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"rule"`
			State           string `json:"state"`
			CreatedAt       string `json:"created_at"`
			DismissedReason string `json:"dismissed_reason"`
			DismissedBy     *struct {
				Login string `json:"login"`
			} `json:"dismissed_by"`
			MostRecentInstance *struct {
				Location *struct {
					Path string `json:"path"`
				} `json:"location"`
			} `json:"most_recent_instance"`
		}
		if err := json.Unmarshal(r, &a); err != nil {
			return nil, false, fmt.Errorf("%s: decoding alert: %w", trimQuery(path), err)
		}
		alert := CodeScanningAlert{
			Repository:      owner + "/" + repo,
			Number:          a.Number,
			RuleID:          a.Rule.ID,
			Severity:        a.Rule.Severity,
			State:           a.State,
			CreatedAt:       a.CreatedAt,
			DismissedReason: a.DismissedReason,
		}
		if a.DismissedBy != nil {
			alert.DismissedBy = a.DismissedBy.Login
		}
		if a.MostRecentInstance != nil && a.MostRecentInstance.Location != nil {
			alert.LocationPath = a.MostRecentInstance.Location.Path
		}
		out = append(out, alert)
	}
	return out, more, nil
}

// ListDependabotAlerts returns open Dependabot alerts for a repo.
func (c *Client) ListDependabotAlerts(ctx context.Context, owner, repo string) ([]DependabotAlert, bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open&per_page=100", owner, repo)
	raw, more, err := c.getAlertPages(ctx, "github.dependabot_alerts.list", path)
	if err != nil {
		return nil, false, err
	}
	out := make([]DependabotAlert, 0, len(raw))
	for _, r := range raw {
		var a struct {
			Number           int    `json:"number"`
			State            string `json:"state"`
			CreatedAt        string `json:"created_at"`
			SecurityAdvisory struct {
				CVEID string `json:"cve_id"`
			} `json:"security_advisory"`
			SecurityVulnerability struct {
				Severity string `json:"severity"`
				Package  struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"security_vulnerability"`
		}
		if err := json.Unmarshal(r, &a); err != nil {
			return nil, false, fmt.Errorf("%s: decoding alert: %w", trimQuery(path), err)
		}
		out = append(out, DependabotAlert{
			Repository: owner + "/" + repo,
			Number:     a.Number,
			Package:    a.SecurityVulnerability.Package.Name,
			Ecosystem:  a.SecurityVulnerability.Package.Ecosystem,
			Severity:   a.SecurityVulnerability.Severity,
			CVE:        a.SecurityAdvisory.CVEID,
			State:      a.State,
			CreatedAt:  a.CreatedAt,
		})
	}
	return out, more, nil
}

// MemberFetchCap bounds login pagination defensively.
const MemberFetchCap = 50000

// getAllLogins pages a members-style endpoint and extracts the "login" field.
func (c *Client) getAllLogins(ctx context.Context, op, firstPath string) ([]string, error) {
	raw, _, err := c.getPagedRaw(ctx, op, firstPath, MemberFetchCap)
	if err != nil {
		return nil, err
	}
	logins := make([]string, 0, len(raw))
	for _, r := range raw {
		var u struct {
			Login string `json:"login"`
		}
		if json.Unmarshal(r, &u) == nil && u.Login != "" {
			logins = append(logins, u.Login)
		}
	}
	return logins, nil
}

// OrgMembership holds the member rosters needed for the Members surface. Each
// roster beyond the member list keeps the error that stopped its read.
type OrgMembership struct {
	Members                 []string
	Admins                  []string
	AdminsErr               error
	OutsideCollaborators    []string
	OutsideCollaboratorsErr error
	// TwoFADisabled is the set of members without 2FA, populated only when the
	// caller is an org owner; nil means the signal was unavailable (so per-user
	// 2FA flags stay unknown rather than wrongly reporting "enabled"), and
	// TwoFAErr says why.
	TwoFADisabled      map[string]bool
	TwoFAErr           error
	PendingInvitations int
	InvitationsErr     error
	// Names maps login to public-profile display name. Logins whose profile has
	// no name set are absent; nil means the lookup itself was unavailable.
	Names map[string]string
	// NamesErr is why the bulk member name query failed, leaving members'
	// names unknown.
	NamesErr error
	// UnnamedCollaborators lists outside collaborators whose names were not
	// looked up because an earlier lookup failed with NameLookupErr.
	UnnamedCollaborators []string
	NameLookupErr        error
	// NamesIncomplete lists reasons name coverage is partial for causes other
	// than users not setting a name (bulk query failed, lookup cap, lookup
	// error), so consumers don't read an absent name as "not set".
	NamesIncomplete []string
}

// GetOrgMembership fetches member rosters. Requires members:read. It returns
// an error only when the member list itself could not be read.
func (c *Client) GetOrgMembership(ctx context.Context, org string) (*OrgMembership, error) {
	members, err := c.getAllLogins(ctx, "github.org_members.list", fmt.Sprintf("/orgs/%s/members?per_page=100", org))
	if err != nil {
		return nil, err
	}
	result := &OrgMembership{Members: members}

	if names, nerr := c.getMemberNames(ctx, org); nerr == nil {
		result.Names = names
	} else {
		result.NamesErr = nerr
		result.NamesIncomplete = append(result.NamesIncomplete, "bulk member name query failed")
	}

	result.Admins, result.AdminsErr = c.getAllLogins(ctx, "github.org_admins.list", fmt.Sprintf("/orgs/%s/members?role=admin&per_page=100", org))
	result.OutsideCollaborators, result.OutsideCollaboratorsErr = c.getAllLogins(ctx, "github.outside_collaborators.list", fmt.Sprintf("/orgs/%s/outside_collaborators?per_page=100", org))
	if result.OutsideCollaboratorsErr == nil {
		lookup := c.collaboratorNames(ctx, result.OutsideCollaborators)
		for l, n := range lookup.names {
			if result.Names == nil {
				result.Names = make(map[string]string, len(lookup.names))
			}
			result.Names[l] = n
		}
		result.NamesIncomplete = append(result.NamesIncomplete, lookup.incomplete...)
		result.UnnamedCollaborators = lookup.unread
		result.NameLookupErr = lookup.err
	}
	if disabled, derr := c.getAllLogins(ctx, "github.org_members_2fa_disabled.list", fmt.Sprintf("/orgs/%s/members?filter=2fa_disabled&per_page=100", org)); derr == nil {
		set := make(map[string]bool, len(disabled))
		for _, l := range disabled {
			set[l] = true
		}
		result.TwoFADisabled = set
	} else {
		result.TwoFAErr = derr
	}
	if inv, _, ierr := c.getPagedRaw(ctx, "github.org_invitations.list", fmt.Sprintf("/orgs/%s/invitations?per_page=100", org), MemberFetchCap); ierr == nil {
		result.PendingInvitations = len(inv)
	} else {
		result.InvitationsErr = ierr
	}

	return result, nil
}

// getMemberNames fetches member display names via GraphQL, the only API that
// returns them in bulk (REST member lists carry logins only). Names are public
// profile data, so this needs no permissions beyond members:read. Outside
// collaborators are absent from membersWithRole; collaboratorNames covers them.
func (c *Client) getMemberNames(ctx context.Context, org string) (map[string]string, error) {
	names := make(map[string]string)
	var cursor *string

	for pages := 0; pages < MemberFetchCap/100; pages++ {
		var data struct {
			Organization *struct {
				MembersWithRole *struct {
					Nodes *[]struct {
						Login string
						Name  string
					}
					PageInfo pageInfo
				}
			}
		}
		if err := c.graphQL(ctx, "github.member_names.list", membersQuery, map[string]any{"org": org, "cursor": cursor}, &data); err != nil {
			return nil, err
		}
		if data.Organization == nil || data.Organization.MembersWithRole == nil || data.Organization.MembersWithRole.Nodes == nil {
			return nil, invalidResponse("graphql members response has no member list")
		}
		page := data.Organization.MembersWithRole
		for _, n := range *page.Nodes {
			if n.Login != "" && n.Name != "" {
				names[n.Login] = n.Name
			}
		}
		if !page.PageInfo.HasNextPage {
			break
		}
		next := page.PageInfo.EndCursor
		cursor = &next
	}

	return names, nil
}

// CollaboratorNameLookupCap bounds per-login name lookups for outside
// collaborators, who have no bulk name API.
const CollaboratorNameLookupCap = 200

// nameLookup is the outcome of looking up outside collaborators' names.
type nameLookup struct {
	names map[string]string
	// incomplete describes any resulting coverage gap.
	incomplete []string
	// unread lists the logins left unlooked-up after a lookup failed with err.
	unread []string
	err    error
}

// collaboratorNames resolves display names for outside collaborators one login
// at a time. A failed lookup aborts the pass: one failure usually means rate
// limiting, so pressing on would just fail the rest too. Deleted users (404)
// are skipped.
func (c *Client) collaboratorNames(ctx context.Context, logins []string) nameLookup {
	var out nameLookup
	if len(logins) > CollaboratorNameLookupCap {
		out.incomplete = append(out.incomplete, fmt.Sprintf("outside-collaborator name lookups capped at %d of %d", CollaboratorNameLookupCap, len(logins)))
		logins = logins[:CollaboratorNameLookupCap]
	}

	out.names = make(map[string]string, len(logins))
	for i, login := range logins {
		name, err := c.getUserName(ctx, login)
		if err != nil {
			out.incomplete = append(out.incomplete, "outside-collaborator name lookups aborted: "+err.Error())
			out.unread = logins[i:]
			out.err = err
			break
		}
		if name != "" {
			out.names[login] = name
		}
	}
	return out
}

// getUserName fetches one user's public-profile display name. A 404 (deleted
// or suspended user) is "no name", not an error.
func (c *Client) getUserName(ctx context.Context, login string) (string, error) {
	path := "/users/" + login
	var user struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := c.getJSON(ctx, "github.users.get", path, &user); err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	if user.Login == "" {
		return "", invalidResponse("%s response has no login", path)
	}
	return user.Name, nil
}

// GetCodeownersInfo reports whether a CODEOWNERS file exists and the path of
// the one GitHub uses, which is the first it finds in .github/, the root, or
// docs/, in that order. When wantHash is true (internal), it also returns a
// SHA-256 of the file's contents. File bytes are hashed in-process and never
// emitted. A file too large to hash is reported present without a hash.
func (c *Client) GetCodeownersInfo(ctx context.Context, owner, repo string, wantHash bool) (present bool, path string, hash string, err error) {
	for _, p := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
		bytes, ferr := c.getFileContents(ctx, owner, repo, p)
		if errors.Is(ferr, ErrNotFound) {
			continue
		}
		if ferr != nil {
			return false, "", "", ferr
		}
		if !wantHash || bytes == nil {
			return true, p, "", nil
		}
		sum := sha256.Sum256(bytes)
		return true, p, hex.EncodeToString(sum[:]), nil
	}
	return false, "", "", nil
}

// codeownersMaxBytes caps the hashable CODEOWNERS size; larger files are
// reported present without a hash.
const codeownersMaxBytes = 1 << 20

// getFileContents fetches and base64-decodes a repo file. It returns nil bytes
// for a file too large to hash or whose content GitHub did not inline. Bytes
// are used only for hashing by the single CODEOWNERS caller.
func (c *Client) getFileContents(ctx context.Context, owner, repo, path string) ([]byte, error) {
	route := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)
	var body struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     *int   `json:"size"`
	}
	if err := c.getJSON(ctx, "github.repo_contents.get", route, &body); err != nil {
		return nil, err
	}
	if body.Size == nil {
		return nil, invalidResponse("%s response has no size", route)
	}
	if *body.Size > codeownersMaxBytes || body.Encoding != "base64" {
		return nil, nil
	}
	// LINT-ALLOW: bytes are SHA-256 hashed by the caller and immediately discarded; never emitted.
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body.Content, "\n", ""))
	if err != nil {
		return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: decoding content: %w", route, err))
	}
	return decoded, nil
}

// Hook is a webhook (org- or repo-level). Only the URL host is retained; the
// full URL, query, and secret are never emitted.
type Hook struct {
	ID                 int64    `json:"id"`
	Active             bool     `json:"active"`
	ContentType        string   `json:"content_type,omitempty"`
	Events             []string `json:"events,omitempty"`
	URLHost            string   `json:"url_host,omitempty"`
	LastResponseCode   int      `json:"last_response_code,omitempty"`
	LastResponseStatus string   `json:"last_response_status,omitempty"`
}

func (c *Client) listHooks(ctx context.Context, op, path string) ([]Hook, error) {
	raw, _, err := c.getPagedRaw(ctx, op, path, 200)
	if err != nil {
		return nil, err
	}
	out := make([]Hook, 0, len(raw))
	for _, r := range raw {
		var h struct {
			ID     int64    `json:"id"`
			Active bool     `json:"active"`
			Events []string `json:"events"`
			Config struct {
				ContentType string `json:"content_type"`
				URL         string `json:"url"`
			} `json:"config"`
			LastResponse struct {
				Code   int    `json:"code"`
				Status string `json:"status"`
			} `json:"last_response"`
		}
		if err := json.Unmarshal(r, &h); err != nil {
			return nil, fmt.Errorf("%s: decoding hook: %w", trimQuery(path), err)
		}
		out = append(out, Hook{
			ID:                 h.ID,
			Active:             h.Active,
			ContentType:        h.Config.ContentType,
			Events:             h.Events,
			URLHost:            hostOnly(h.Config.URL),
			LastResponseCode:   h.LastResponse.Code,
			LastResponseStatus: h.LastResponse.Status,
		})
	}
	return out, nil
}

// ListOrgHooks returns org-level webhooks. Requires organization_hooks:read.
func (c *Client) ListOrgHooks(ctx context.Context, org string) ([]Hook, error) {
	return c.listHooks(ctx, "github.org_hooks.list", fmt.Sprintf("/orgs/%s/hooks?per_page=100", org))
}

// ListRepoHooks returns repo-level webhooks. Requires repository_hooks:read.
func (c *Client) ListRepoHooks(ctx context.Context, owner, repo string) ([]Hook, error) {
	return c.listHooks(ctx, "github.repo_hooks.list", fmt.Sprintf("/repos/%s/%s/hooks?per_page=100", owner, repo))
}

// hostOnly extracts the host from a URL, dropping path/query/secret material.
func hostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// DeployKey is a repo deploy key. The public key is fingerprinted, not emitted.
type DeployKey struct {
	Repository  string `json:"repository"`
	ID          int64  `json:"id"`
	Title       string `json:"title,omitempty"`
	ReadOnly    bool   `json:"read_only"`
	CreatedAt   string `json:"created_at,omitempty"`
	LastUsed    string `json:"last_used,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ListRepoDeployKeys returns deploy keys for a repo. Requires administration:read.
func (c *Client) ListRepoDeployKeys(ctx context.Context, owner, repo string) ([]DeployKey, error) {
	path := fmt.Sprintf("/repos/%s/%s/keys?per_page=100", owner, repo)
	raw, _, err := c.getPagedRaw(ctx, "github.deploy_keys.list", path, 1000)
	if err != nil {
		return nil, err
	}
	out := make([]DeployKey, 0, len(raw))
	for _, r := range raw {
		var k struct {
			ID        int64  `json:"id"`
			Title     string `json:"title"`
			ReadOnly  bool   `json:"read_only"`
			CreatedAt string `json:"created_at"`
			LastUsed  string `json:"last_used"`
			Key       string `json:"key"`
		}
		if err := json.Unmarshal(r, &k); err != nil {
			return nil, fmt.Errorf("%s: decoding deploy key: %w", trimQuery(path), err)
		}
		dk := DeployKey{
			Repository: owner + "/" + repo,
			ID:         k.ID,
			Title:      k.Title,
			ReadOnly:   k.ReadOnly,
			CreatedAt:  k.CreatedAt,
			LastUsed:   k.LastUsed,
		}
		if k.Key != "" {
			sum := sha256.Sum256([]byte(k.Key))
			dk.Fingerprint = hex.EncodeToString(sum[:])
		}
		out = append(out, dk)
	}
	return out, nil
}

// Runner is a self-hosted Actions runner (org- or repo-level).
type Runner struct {
	ID     int64    `json:"id"`
	Name   string   `json:"name,omitempty"`
	OS     string   `json:"os,omitempty"`
	Status string   `json:"status,omitempty"`
	Busy   bool     `json:"busy"`
	Labels []string `json:"labels,omitempty"`
}

func (c *Client) listRunners(ctx context.Context, op, path string) ([]Runner, int, error) {
	raw, total, err := c.getPagedTotal(ctx, op, path, "runners", InventoryFetchCap)
	if err != nil {
		return nil, 0, err
	}
	out := make([]Runner, 0, len(raw))
	for _, item := range raw {
		var r struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			OS     string `json:"os"`
			Status string `json:"status"`
			Busy   bool   `json:"busy"`
			Labels []struct {
				Name string `json:"name"`
			} `json:"labels"`
		}
		if err := json.Unmarshal(item, &r); err != nil {
			return nil, 0, fmt.Errorf("%s: decoding runner: %w", trimQuery(path), err)
		}
		labels := make([]string, 0, len(r.Labels))
		for _, l := range r.Labels {
			labels = append(labels, l.Name)
		}
		out = append(out, Runner{ID: r.ID, Name: r.Name, OS: r.OS, Status: r.Status, Busy: r.Busy, Labels: labels})
	}
	return out, total, nil
}

// ListOrgRunners returns org-level self-hosted runners, up to
// InventoryFetchCap, and the count GitHub reports. Requires
// organization_self_hosted_runners:read.
func (c *Client) ListOrgRunners(ctx context.Context, org string) ([]Runner, int, error) {
	return c.listRunners(ctx, "github.org_runners.list", fmt.Sprintf("/orgs/%s/actions/runners?per_page=100", org))
}

// ListRepoRunners returns repo-level self-hosted runners, up to
// InventoryFetchCap, and the count GitHub reports. Requires actions:read.
func (c *Client) ListRepoRunners(ctx context.Context, owner, repo string) ([]Runner, int, error) {
	return c.listRunners(ctx, "github.repo_runners.list", fmt.Sprintf("/repos/%s/%s/actions/runners?per_page=100", owner, repo))
}

// ListOrgActionsSecretNames returns org-level Actions secret names (never
// values), up to InventoryFetchCap, and the count GitHub reports. Requires
// organization_secrets:read.
func (c *Client) ListOrgActionsSecretNames(ctx context.Context, org string) ([]string, int, error) {
	path := fmt.Sprintf("/orgs/%s/actions/secrets?per_page=100", org)
	raw, total, err := c.getPagedTotal(ctx, "github.org_actions_secrets.list", path, "secrets", InventoryFetchCap)
	if err != nil {
		return nil, 0, err
	}
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		var s struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(item, &s); err != nil {
			return nil, 0, fmt.Errorf("%s: decoding secret: %w", trimQuery(path), err)
		}
		names = append(names, s.Name)
	}
	return names, total, nil
}

// AuditEvent is one security-relevant org audit-log event (internal level).
type AuditEvent struct {
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	Repo      string `json:"repo,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// AuditLogCategories are the security-relevant action prefixes the audit-log
// surface queries (never a full log dump).
var AuditLogCategories = []string{
	"member_", "repo.create", "repo.transfer", "repo.destroy", "repo.access",
	"protected_branch.", "oauth_application.", "secret_scanning_alert.bypass",
	"org.disable_two_factor_requirement", "org.update_member",
}

// GetOrgAuditLog fetches security-relevant audit events since sinceISO.
// Returns ErrFeatureUnavailable, coded not_licensed, when GitHub answers 404,
// as it does for organizations without Enterprise Cloud. maxEvents bounds
// fetch.
func (c *Client) GetOrgAuditLog(ctx context.Context, org, sinceISO string, maxEvents int) ([]AuditEvent, bool, error) {
	phrase := "created:>=" + sinceISO
	path := fmt.Sprintf("/orgs/%s/audit-log?phrase=%s&per_page=100", org, url.QueryEscape(phrase))
	raw, more, err := c.getPagedRaw(ctx, "github.audit_log.list", path, maxEvents)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, false, featureUnavailable(err, "the audit log API requires GitHub Enterprise Cloud")
		}
		return nil, false, err
	}
	out := make([]AuditEvent, 0, len(raw))
	for _, r := range raw {
		var e struct {
			Action    string `json:"action"`
			Actor     string `json:"actor"`
			Repo      string `json:"repo"`
			CreatedAt int64  `json:"created_at"`
		}
		if err := json.Unmarshal(r, &e); err != nil {
			return nil, false, fmt.Errorf("%s: decoding audit event: %w", trimQuery(path), err)
		}
		if !isSecurityRelevantAction(e.Action) {
			continue
		}
		out = append(out, AuditEvent{Action: e.Action, Actor: e.Actor, Repo: e.Repo, CreatedAt: e.CreatedAt})
	}
	return out, more, nil
}

func isSecurityRelevantAction(action string) bool {
	for _, cat := range AuditLogCategories {
		if strings.HasSuffix(cat, ".") || strings.HasSuffix(cat, "_") {
			if strings.HasPrefix(action, cat) {
				return true
			}
		} else if action == cat {
			return true
		}
	}
	return false
}

// Installation is a GitHub App installed in the org (distinct from the App the
// collector runs as).
type Installation struct {
	AppSlug             string            `json:"app_slug,omitempty"`
	AppID               int64             `json:"app_id"`
	Suspended           bool              `json:"suspended"`
	Permissions         map[string]string `json:"permissions,omitempty"`
	CreatedAt           string            `json:"created_at,omitempty"`
	UpdatedAt           string            `json:"updated_at,omitempty"`
	RepositorySelection string            `json:"repository_selection,omitempty"`
	Events              []string          `json:"events,omitempty"`
}

// ListOrgInstallations returns Apps installed in the org, up to
// InventoryFetchCap, and the count GitHub reports. Requires
// organization_administration:read.
func (c *Client) ListOrgInstallations(ctx context.Context, org string) ([]Installation, int, error) {
	path := fmt.Sprintf("/orgs/%s/installations?per_page=100", org)
	raw, total, err := c.getPagedTotal(ctx, "github.org_installations.list", path, "installations", InventoryFetchCap)
	if err != nil {
		return nil, 0, err
	}
	out := make([]Installation, 0, len(raw))
	for _, item := range raw {
		var i struct {
			AppSlug             string            `json:"app_slug"`
			AppID               int64             `json:"app_id"`
			SuspendedAt         *string           `json:"suspended_at"`
			Permissions         map[string]string `json:"permissions"`
			CreatedAt           string            `json:"created_at"`
			UpdatedAt           string            `json:"updated_at"`
			RepositorySelection string            `json:"repository_selection"`
			Events              []string          `json:"events"`
		}
		if err := json.Unmarshal(item, &i); err != nil {
			return nil, 0, fmt.Errorf("%s: decoding installation: %w", trimQuery(path), err)
		}
		out = append(out, Installation{
			AppSlug:             i.AppSlug,
			AppID:               i.AppID,
			Suspended:           i.SuspendedAt != nil,
			Permissions:         i.Permissions,
			CreatedAt:           i.CreatedAt,
			UpdatedAt:           i.UpdatedAt,
			RepositorySelection: i.RepositorySelection,
			Events:              i.Events,
		})
	}
	return out, total, nil
}

// Deployment branch policy modes for an environment. "any" means no
// restriction, "protected_branches" limits deployments to branches with
// protection rules, "custom" limits them to named branch / tag patterns.
const (
	BranchPolicyAny       = "any"
	BranchPolicyProtected = "protected_branches"
	BranchPolicyCustom    = "custom"
)

// Environment is one repository deployment environment and its protection
// configuration. CanAdminsBypass is a pointer: nil means the API did not
// return the field, not "bypass disabled".
type Environment struct {
	Name                 string
	CreatedAt            string
	UpdatedAt            string
	HasRequiredReviewers bool
	PreventSelfReview    bool
	Reviewers            []EnvironmentReviewer
	WaitTimerMinutes     int
	BranchPolicy         string
	CanAdminsBypass      *bool
}

// EnvironmentReviewer is one required reviewer on an environment: a user
// (login) or a team (slug + display name).
type EnvironmentReviewer struct {
	Type  string
	Login string
	Slug  string
	Name  string
}

// BranchPolicyPattern is one branch / tag name pattern allowed to deploy to
// an environment with a custom deployment branch policy.
type BranchPolicyPattern struct {
	Name string
	Type string
}

// EnvironmentFetchCap bounds per-repo environment pagination defensively
// (repos that create per-preview environments can accumulate hundreds).
const EnvironmentFetchCap = 1000

// ListRepoEnvironments returns a repo's deployment environments with their
// protection configuration. total is the repo's full environment count, which
// can exceed len(envs) when the fetch cap truncates. A 404 means the
// repository has no environments. Requires actions:read.
func (c *Client) ListRepoEnvironments(ctx context.Context, owner, repo string) (envs []Environment, total int, err error) {
	for page := 1; page <= EnvironmentFetchCap/100; page++ {
		var body struct {
			TotalCount   int                `json:"total_count"`
			Environments *[]json.RawMessage `json:"environments"`
		}
		path := fmt.Sprintf("/repos/%s/%s/environments?per_page=100&page=%d", owner, repo, page)
		if err := c.getJSON(ctx, "github.environments.list", path, &body); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, 0, nil
			}
			return nil, 0, err
		}
		if body.Environments == nil {
			return nil, 0, invalidResponse("%s response has no environments list", trimQuery(path))
		}
		total = body.TotalCount
		for _, raw := range *body.Environments {
			e, ok := parseEnvironment(raw)
			if !ok {
				return nil, 0, invalidResponse("%s response has an environment that does not parse", trimQuery(path))
			}
			envs = append(envs, e)
		}
		if len(*body.Environments) < 100 {
			break
		}
	}
	return envs, total, nil
}

func parseEnvironment(raw json.RawMessage) (Environment, bool) {
	var e struct {
		Name            string `json:"name"`
		CreatedAt       string `json:"created_at"`
		UpdatedAt       string `json:"updated_at"`
		CanAdminsBypass *bool  `json:"can_admins_bypass"`
		ProtectionRules []struct {
			Type              string `json:"type"`
			WaitTimer         int    `json:"wait_timer"`
			PreventSelfReview bool   `json:"prevent_self_review"`
			Reviewers         []struct {
				Type     string `json:"type"`
				Reviewer struct {
					Login string `json:"login"`
					Slug  string `json:"slug"`
					Name  string `json:"name"`
				} `json:"reviewer"`
			} `json:"reviewers"`
		} `json:"protection_rules"`
		DeploymentBranchPolicy *struct {
			ProtectedBranches    bool `json:"protected_branches"`
			CustomBranchPolicies bool `json:"custom_branch_policies"`
		} `json:"deployment_branch_policy"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return Environment{}, false
	}

	env := Environment{
		Name:            e.Name,
		CreatedAt:       e.CreatedAt,
		UpdatedAt:       e.UpdatedAt,
		CanAdminsBypass: e.CanAdminsBypass,
		BranchPolicy:    BranchPolicyAny,
	}
	if e.DeploymentBranchPolicy != nil {
		switch {
		case e.DeploymentBranchPolicy.CustomBranchPolicies:
			env.BranchPolicy = BranchPolicyCustom
		case e.DeploymentBranchPolicy.ProtectedBranches:
			env.BranchPolicy = BranchPolicyProtected
		}
	}
	for _, rule := range e.ProtectionRules {
		switch rule.Type {
		case "required_reviewers":
			env.HasRequiredReviewers = true
			env.PreventSelfReview = rule.PreventSelfReview
			for _, rv := range rule.Reviewers {
				env.Reviewers = append(env.Reviewers, EnvironmentReviewer{
					Type:  rv.Type,
					Login: rv.Reviewer.Login,
					Slug:  rv.Reviewer.Slug,
					Name:  rv.Reviewer.Name,
				})
			}
		case "wait_timer":
			env.WaitTimerMinutes = rule.WaitTimer
		}
	}
	return env, true
}

// ListEnvironmentBranchPolicies returns the branch / tag name patterns allowed
// to deploy to an environment with a custom deployment branch policy. A 404
// means the environment has none. Requires actions:read.
func (c *Client) ListEnvironmentBranchPolicies(ctx context.Context, owner, repo, environment string) ([]BranchPolicyPattern, error) {
	var body struct {
		BranchPolicies *[]struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"branch_policies"`
	}
	path := fmt.Sprintf("/repos/%s/%s/environments/%s/deployment-branch-policies?per_page=100", owner, repo, url.PathEscape(environment))
	if err := c.getJSON(ctx, "github.environment_branch_policies.list", path, &body); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if body.BranchPolicies == nil {
		return nil, invalidResponse("%s response has no branch_policies list", trimQuery(path))
	}
	out := make([]BranchPolicyPattern, 0, len(*body.BranchPolicies))
	for _, p := range *body.BranchPolicies {
		out = append(out, BranchPolicyPattern{Name: p.Name, Type: p.Type})
	}
	return out, nil
}

// ListEnvironmentProtectionApps returns the slugs of GitHub Apps enforcing
// enabled custom deployment protection rules on an environment. A 404 means
// the environment has none. Requires actions:read.
func (c *Client) ListEnvironmentProtectionApps(ctx context.Context, owner, repo, environment string) ([]string, error) {
	var body struct {
		Rules *[]struct {
			Enabled bool `json:"enabled"`
			App     struct {
				Slug string `json:"slug"`
			} `json:"app"`
		} `json:"custom_deployment_protection_rules"`
	}
	path := fmt.Sprintf("/repos/%s/%s/environments/%s/deployment_protection_rules?per_page=100", owner, repo, url.PathEscape(environment))
	if err := c.getJSON(ctx, "github.environment_protection_rules.list", path, &body); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if body.Rules == nil {
		return nil, invalidResponse("%s response has no custom_deployment_protection_rules list", trimQuery(path))
	}
	var slugs []string
	for _, r := range *body.Rules {
		if r.Enabled && r.App.Slug != "" {
			slugs = append(slugs, r.App.Slug)
		}
	}
	return slugs, nil
}

// PATGrant is a fine-grained PAT granted access to org resources (internal).
type PATGrant struct {
	ID          int64    `json:"id"`
	Owner       string   `json:"owner,omitempty"`
	TokenName   string   `json:"token_name,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	LastUsed    string   `json:"last_used,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// ListOrgPATs returns fine-grained PATs with access to the org. Returns
// ErrFeatureUnavailable, coded not_licensed, when GitHub answers 404, as it
// does for orgs without a fine-grained-token policy. Token values are never
// exposed by the API and never emitted.
func (c *Client) ListOrgPATs(ctx context.Context, org string) ([]PATGrant, bool, error) {
	path := fmt.Sprintf("/orgs/%s/personal-access-tokens?per_page=100", org)
	raw, more, err := c.getPagedRaw(ctx, "github.org_personal_access_tokens.list", path, 5000)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, false, featureUnavailable(err, "the organization has no fine-grained personal access token policy")
		}
		return nil, false, err
	}
	out := make([]PATGrant, 0, len(raw))
	for _, r := range raw {
		var p struct {
			ID    int64 `json:"id"`
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
			TokenName       string                       `json:"token_name"`
			Permissions     map[string]map[string]string `json:"permissions"`
			TokenLastUsedAt string                       `json:"token_last_used_at"`
			TokenExpiresAt  string                       `json:"token_expires_at"`
		}
		if err := json.Unmarshal(r, &p); err != nil {
			return nil, false, fmt.Errorf("%s: decoding token grant: %w", trimQuery(path), err)
		}
		perms := make([]string, 0)
		for scope, actions := range p.Permissions {
			for name := range actions {
				perms = append(perms, scope+":"+name)
			}
		}
		sort.Strings(perms)
		out = append(out, PATGrant{
			ID:          p.ID,
			Owner:       p.Owner.Login,
			TokenName:   p.TokenName,
			Permissions: perms,
			LastUsed:    p.TokenLastUsedAt,
			ExpiresAt:   p.TokenExpiresAt,
		})
	}
	return out, more, nil
}
