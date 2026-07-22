package github

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/shurcooL/githubv4"
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

// classifyStatus maps a non-200 REST response to a sentinel-wrapped error:
// 404→ErrNotFound; 403→ErrFeatureUnavailable when the body says the feature is
// off, otherwise ErrPermissionDenied; anything else→a generic error. Callers
// that treat 404 as "empty/feature off" branch on errors.Is(ErrNotFound).
func classifyStatus(resp *http.Response, path string) error {
	switch resp.StatusCode {
	case http.StatusForbidden:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if is403FeatureDisabled(string(body)) {
			return fmt.Errorf("%w: %s (403: feature not enabled)", ErrFeatureUnavailable, path)
		}
		return fmt.Errorf("%w: %s (status 403)", ErrPermissionDenied, path)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s (status 404)", ErrNotFound, path)
	default:
		return fmt.Errorf("%s returned status %d", path, resp.StatusCode)
	}
}

// getJSON performs a GET against the REST API and decodes the body into out.
// It maps 403→ErrPermissionDenied and 404→ErrNotFound so callers can branch
// on expected outcomes.
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	setAPIHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return classifyStatus(resp, path)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// OrgSettings holds org-level access-control settings surfaced at audit level.
// Pointer fields are nil when the API does not reliably expose the value
// (matching the existing 2FA-nullable convention).
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
	var body struct {
		DefaultRepositoryPermission  string `json:"default_repository_permission"`
		MembersCanCreateRepositories *bool  `json:"members_can_create_repositories"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("/orgs/%s", org), &body); err != nil {
		return nil, err
	}
	return &OrgSettings{
		DefaultRepositoryPermission:  body.DefaultRepositoryPermission,
		MembersCanCreateRepositories: body.MembersCanCreateRepositories,
	}, nil
}

// AlertType identifies a GitHub Advanced Security alert endpoint.
type AlertType string

const (
	AlertSecretScanning AlertType = "secret-scanning"
	AlertCodeScanning   AlertType = "code-scanning"
	AlertDependabot     AlertType = "dependabot"
)

var linkLastPageRe = regexp.MustCompile(`[?&]page=(\d+)[^>]*>;\s*rel="last"`)

// getOpenAlertTotal returns the count of open alerts for a repo+type using the
// per_page=1 + Link-header trick: the "last" page number equals the total. On
// 404 (feature not enabled for the repo) it returns 0 with no error.
func (c *Client) getOpenAlertTotal(ctx context.Context, owner, repo string, alertType AlertType) (int, error) {
	path := fmt.Sprintf("/repos/%s/%s/%s/alerts?state=open&per_page=1", owner, repo, alertType)
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	setAPIHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		err := classifyStatus(resp, path)
		if errors.Is(err, ErrNotFound) {
			// Feature not enabled for this repo: zero open alerts, not an error.
			return 0, nil
		}
		return 0, err
	}
	// If there's a "last" page, total == last page number (per_page=1).
	if m := linkLastPageRe.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			return n, nil
		}
	}
	// No Link header: the result fits on one page. Count the items.
	var items []json.RawMessage
	if decErr := json.NewDecoder(resp.Body).Decode(&items); decErr != nil {
		return 0, nil
	}
	return len(items), nil
}

// GetOpenAlertCounts returns the open-alert totals for a repo across the three
// Advanced Security alert types. If any type fails, the returned error favors a
// permission denial (actionable: grant the scope) over a feature-not-enabled
// signal (informational); callers record the matching diagnostic and continue
// with whatever counts succeeded.
func (c *Client) GetOpenAlertCounts(ctx context.Context, owner, repo string) (*AlertCounts, error) {
	counts := &AlertCounts{}
	var permErr, featErr error
	for _, t := range []AlertType{AlertSecretScanning, AlertCodeScanning, AlertDependabot} {
		n, err := c.getOpenAlertTotal(ctx, owner, repo, t)
		if err != nil {
			switch {
			case errors.Is(err, ErrPermissionDenied) && permErr == nil:
				permErr = err
			case errors.Is(err, ErrFeatureUnavailable) && featErr == nil:
				featErr = err
			}
			continue
		}
		switch t {
		case AlertSecretScanning:
			counts.SecretScanningOpen = n
		case AlertCodeScanning:
			counts.CodeScanningOpen = n
		case AlertDependabot:
			counts.DependabotOpen = n
		}
	}
	if permErr != nil {
		return counts, permErr
	}
	return counts, featErr
}

// AlertCounts holds open-alert totals for a repository.
type AlertCounts struct {
	SecretScanningOpen int
	CodeScanningOpen   int
	DependabotOpen     int
}

// AlertFetchCap bounds how many alerts of one type are fetched per repo, so a
// long-neglected inventory can't blow the per-collector output limit. The
// collector truncates to its own cap and flags it; this is the upstream guard.
const AlertFetchCap = 5001

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// getPagedRaw follows Link rel="next" pagination accumulating raw JSON array
// elements, stopping at maxItems. 404 → empty (feature not enabled). 403 →
// ErrPermissionDenied, or ErrFeatureUnavailable when the body says the feature
// is off. The returned bool reports whether more pages existed beyond maxItems.
func (c *Client) getPagedRaw(ctx context.Context, firstPath string, maxItems int) ([]json.RawMessage, bool, error) {
	var all []json.RawMessage
	next := c.baseURL + firstPath

	for next != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", next, nil)
		if err != nil {
			return nil, false, err
		}
		setAPIHeaders(req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, false, err
		}

		if resp.StatusCode != http.StatusOK {
			err := classifyStatus(resp, firstPath)
			_ = resp.Body.Close()
			if errors.Is(err, ErrNotFound) {
				// Feature not enabled: return whatever pages accumulated so far.
				return all, false, nil
			}
			return nil, false, err
		}

		var page []json.RawMessage
		decErr := json.NewDecoder(resp.Body).Decode(&page)
		link := resp.Header.Get("Link")
		_ = resp.Body.Close()
		if decErr != nil {
			return all, false, nil
		}
		all = append(all, page...)
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
	path := fmt.Sprintf("/repos/%s/%s/secret-scanning/alerts?state=open&per_page=100", owner, repo)
	raw, more, err := c.getPagedRaw(ctx, path, AlertFetchCap)
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
		if json.Unmarshal(r, &a) != nil {
			continue
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
	raw, more, err := c.getPagedRaw(ctx, path, AlertFetchCap)
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
		if json.Unmarshal(r, &a) != nil {
			continue
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
	raw, more, err := c.getPagedRaw(ctx, path, AlertFetchCap)
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
		if json.Unmarshal(r, &a) != nil {
			continue
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
func (c *Client) getAllLogins(ctx context.Context, firstPath string) ([]string, error) {
	raw, _, err := c.getPagedRaw(ctx, firstPath, MemberFetchCap)
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

// OrgMembership holds the member rosters needed for the Members surface.
type OrgMembership struct {
	Members              []string
	Admins               []string
	OutsideCollaborators []string
	// TwoFADisabled is the set of members without 2FA, populated only when the
	// caller is an org owner; nil means the signal was unavailable (so per-user
	// 2FA flags stay unknown rather than wrongly reporting "enabled").
	TwoFADisabled      map[string]bool
	PendingInvitations int
	// Names maps login to public-profile display name. Logins whose profile has
	// no name set are absent; nil means the lookup itself was unavailable.
	Names map[string]string
	// NamesIncomplete lists reasons name coverage is partial for causes other
	// than users not setting a name (bulk query failed, lookup cap, lookup
	// error), so consumers don't read an absent name as "not set".
	NamesIncomplete []string
}

// GetOrgMembership fetches member rosters. Requires members:read.
func (c *Client) GetOrgMembership(ctx context.Context, org string) (*OrgMembership, error) {
	members, err := c.getAllLogins(ctx, fmt.Sprintf("/orgs/%s/members?per_page=100", org))
	if err != nil {
		return nil, err
	}
	result := &OrgMembership{Members: members}

	if names, nerr := c.getMemberNames(ctx, org); nerr == nil {
		result.Names = names
	} else {
		result.NamesIncomplete = append(result.NamesIncomplete, "bulk member name query failed")
	}

	if admins, aerr := c.getAllLogins(ctx, fmt.Sprintf("/orgs/%s/members?role=admin&per_page=100", org)); aerr == nil {
		result.Admins = admins
	}
	if oc, oerr := c.getAllLogins(ctx, fmt.Sprintf("/orgs/%s/outside_collaborators?per_page=100", org)); oerr == nil {
		result.OutsideCollaborators = oc
		names, incomplete := c.collaboratorNames(ctx, oc)
		for l, n := range names {
			if result.Names == nil {
				result.Names = make(map[string]string, len(names))
			}
			result.Names[l] = n
		}
		result.NamesIncomplete = append(result.NamesIncomplete, incomplete...)
	}
	if disabled, derr := c.getAllLogins(ctx, fmt.Sprintf("/orgs/%s/members?filter=2fa_disabled&per_page=100", org)); derr == nil {
		set := make(map[string]bool, len(disabled))
		for _, l := range disabled {
			set[l] = true
		}
		result.TwoFADisabled = set
	}
	if inv, _, ierr := c.getPagedRaw(ctx, fmt.Sprintf("/orgs/%s/invitations?per_page=100", org), MemberFetchCap); ierr == nil {
		result.PendingInvitations = len(inv)
	}

	return result, nil
}

// getMemberNames fetches member display names via GraphQL, the only API that
// returns them in bulk (REST member lists carry logins only). Names are public
// profile data, so this needs no permissions beyond members:read. Outside
// collaborators are absent from membersWithRole; collaboratorNames covers them.
func (c *Client) getMemberNames(ctx context.Context, org string) (map[string]string, error) {
	if c.graphql == nil {
		return nil, errors.New("graphql client not configured")
	}

	names := make(map[string]string)
	var cursor *githubv4.String

	for pages := 0; pages < MemberFetchCap/100; pages++ {
		var query MembersWithRoleQuery
		variables := map[string]interface{}{
			"org":    githubv4.String(org),
			"cursor": cursor,
		}
		if err := c.graphql.Query(ctx, &query, variables); err != nil {
			return nil, err
		}
		for _, n := range query.Organization.MembersWithRole.Nodes {
			if n.Login != "" && n.Name != "" {
				names[n.Login] = n.Name
			}
		}
		if !query.Organization.MembersWithRole.PageInfo.HasNextPage {
			break
		}
		cursor = &query.Organization.MembersWithRole.PageInfo.EndCursor
	}

	return names, nil
}

// CollaboratorNameLookupCap bounds per-login name lookups for outside
// collaborators, who have no bulk name API.
const CollaboratorNameLookupCap = 200

// collaboratorNames resolves display names for outside collaborators one login
// at a time. A failed lookup aborts the pass: one failure usually means rate
// limiting, so pressing on would just fail the rest too. Deleted users (404)
// are skipped. Returned reasons describe any resulting coverage gap.
func (c *Client) collaboratorNames(ctx context.Context, logins []string) (map[string]string, []string) {
	var incomplete []string
	if len(logins) > CollaboratorNameLookupCap {
		incomplete = append(incomplete, fmt.Sprintf("outside-collaborator name lookups capped at %d of %d", CollaboratorNameLookupCap, len(logins)))
		logins = logins[:CollaboratorNameLookupCap]
	}

	names := make(map[string]string, len(logins))
	for _, login := range logins {
		name, err := c.getUserName(ctx, login)
		if err != nil {
			incomplete = append(incomplete, "outside-collaborator name lookups aborted: "+err.Error())
			break
		}
		if name != "" {
			names[login] = name
		}
	}
	return names, incomplete
}

// getUserName fetches one user's public-profile display name. A 404 (deleted
// or suspended user) is "no name", not an error.
func (c *Client) getUserName(ctx context.Context, login string) (string, error) {
	var user struct {
		Name string `json:"name"`
	}
	if err := c.getJSON(ctx, "/users/"+login, &user); err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	return user.Name, nil
}

// GetCodeownersInfo reports whether a CODEOWNERS file exists (and its path) and,
// when wantHash is true (internal), a SHA-256 of its contents. File bytes are
// hashed in-process and never emitted.
func (c *Client) GetCodeownersInfo(ctx context.Context, owner, repo string, wantHash bool) (present bool, path string, hash string, err error) {
	for _, p := range []string{".github/CODEOWNERS", "docs/CODEOWNERS", "CODEOWNERS"} {
		bytes, ferr := c.getFileContents(ctx, owner, repo, p)
		if errors.Is(ferr, ErrNotFound) {
			continue
		}
		if ferr != nil {
			return false, "", "", ferr
		}
		if !wantHash {
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

// getFileContents fetches and base64-decodes a repo file. Bytes are used only
// for hashing by the single CODEOWNERS caller.
func (c *Client) getFileContents(ctx context.Context, owner, repo, path string) ([]byte, error) {
	var body struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     int    `json:"size"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path), &body); err != nil {
		return nil, err
	}
	if body.Size > codeownersMaxBytes || body.Encoding != "base64" {
		return nil, ErrNotFound
	}
	// LINT-ALLOW: bytes are SHA-256 hashed by the caller and immediately discarded; never emitted.
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body.Content, "\n", ""))
	if err != nil {
		return nil, err
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

func (c *Client) listHooks(ctx context.Context, path string) ([]Hook, error) {
	raw, _, err := c.getPagedRaw(ctx, path, 200)
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
		if json.Unmarshal(r, &h) != nil {
			continue
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
	return c.listHooks(ctx, fmt.Sprintf("/orgs/%s/hooks?per_page=100", org))
}

// ListRepoHooks returns repo-level webhooks. Requires repository_hooks:read.
func (c *Client) ListRepoHooks(ctx context.Context, owner, repo string) ([]Hook, error) {
	return c.listHooks(ctx, fmt.Sprintf("/repos/%s/%s/hooks?per_page=100", owner, repo))
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
	raw, _, err := c.getPagedRaw(ctx, fmt.Sprintf("/repos/%s/%s/keys?per_page=100", owner, repo), 1000)
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
		if json.Unmarshal(r, &k) != nil {
			continue
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

func (c *Client) listRunners(ctx context.Context, path string) ([]Runner, error) {
	var body struct {
		Runners []struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			OS     string `json:"os"`
			Status string `json:"status"`
			Busy   bool   `json:"busy"`
			Labels []struct {
				Name string `json:"name"`
			} `json:"labels"`
		} `json:"runners"`
	}
	if err := c.getJSON(ctx, path, &body); err != nil {
		return nil, err
	}
	out := make([]Runner, 0, len(body.Runners))
	for _, r := range body.Runners {
		labels := make([]string, 0, len(r.Labels))
		for _, l := range r.Labels {
			labels = append(labels, l.Name)
		}
		out = append(out, Runner{ID: r.ID, Name: r.Name, OS: r.OS, Status: r.Status, Busy: r.Busy, Labels: labels})
	}
	return out, nil
}

// ListOrgRunners returns org-level self-hosted runners. Requires
// organization_self_hosted_runners:read.
func (c *Client) ListOrgRunners(ctx context.Context, org string) ([]Runner, error) {
	return c.listRunners(ctx, fmt.Sprintf("/orgs/%s/actions/runners?per_page=100", org))
}

// ListRepoRunners returns repo-level self-hosted runners. Requires actions:read.
func (c *Client) ListRepoRunners(ctx context.Context, owner, repo string) ([]Runner, error) {
	return c.listRunners(ctx, fmt.Sprintf("/repos/%s/%s/actions/runners?per_page=100", owner, repo))
}

// ListOrgActionsSecretNames returns org-level Actions secret names (never
// values). Requires organization_secrets:read.
func (c *Client) ListOrgActionsSecretNames(ctx context.Context, org string) ([]string, error) {
	var body struct {
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("/orgs/%s/actions/secrets?per_page=100", org), &body); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(body.Secrets))
	for _, s := range body.Secrets {
		names = append(names, s.Name)
	}
	return names, nil
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
// Returns ErrFeatureUnavailable on non-Enterprise orgs. maxEvents bounds fetch.
func (c *Client) GetOrgAuditLog(ctx context.Context, org, sinceISO string, maxEvents int) ([]AuditEvent, bool, error) {
	phrase := "created:>=" + sinceISO
	path := fmt.Sprintf("/orgs/%s/audit-log?phrase=%s&per_page=100", org, url.QueryEscape(phrase))
	raw, more, err := c.getPagedRaw(ctx, path, maxEvents)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrPermissionDenied) {
			return nil, false, ErrFeatureUnavailable
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
		if json.Unmarshal(r, &e) != nil {
			continue
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

// ListOrgInstallations returns Apps installed in the org. Requires
// organization_administration:read.
func (c *Client) ListOrgInstallations(ctx context.Context, org string) ([]Installation, error) {
	var body struct {
		Installations []struct {
			AppSlug             string            `json:"app_slug"`
			AppID               int64             `json:"app_id"`
			SuspendedAt         *string           `json:"suspended_at"`
			Permissions         map[string]string `json:"permissions"`
			CreatedAt           string            `json:"created_at"`
			UpdatedAt           string            `json:"updated_at"`
			RepositorySelection string            `json:"repository_selection"`
			Events              []string          `json:"events"`
		} `json:"installations"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("/orgs/%s/installations?per_page=100", org), &body); err != nil {
		return nil, err
	}
	out := make([]Installation, 0, len(body.Installations))
	for _, i := range body.Installations {
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
	return out, nil
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
// ErrFeatureUnavailable on orgs without a fine-grained-token policy. Token
// values are never exposed by the API and never emitted.
func (c *Client) ListOrgPATs(ctx context.Context, org string) ([]PATGrant, bool, error) {
	raw, more, err := c.getPagedRaw(ctx, fmt.Sprintf("/orgs/%s/personal-access-tokens?per_page=100", org), 5000)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrPermissionDenied) {
			return nil, false, ErrFeatureUnavailable
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
		if json.Unmarshal(r, &p) != nil {
			continue
		}
		perms := make([]string, 0)
		for scope, actions := range p.Permissions {
			for name := range actions {
				perms = append(perms, scope+":"+name)
			}
		}
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
