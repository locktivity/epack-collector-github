// Package collector provides GitHub organization posture collection functionality.
package collector

import "time"

// SchemaVersion is the version of the output schema.
const SchemaVersion = "1.0.0"

// StatusFunc is called to report indeterminate status updates.
type StatusFunc func(message string)

// ProgressFunc is called to report determinate progress (current/total).
type ProgressFunc func(current, total int64, message string)

// Config holds the collector configuration passed via stdin.
type Config struct {
	Organization    string   `json:"organization"`
	GitHubToken     string   `json:"github_token"`    // Classic PAT (legacy)
	AppID           int64    `json:"app_id"`          // GitHub App ID (recommended)
	InstallationID  int64    `json:"installation_id"` // GitHub App installation ID
	PrivateKey      string   `json:"private_key"`     // GitHub App private key (PEM)
	IncludePatterns []string `json:"include_patterns"`
	ExcludePatterns []string `json:"exclude_patterns"`

	// Progress callbacks (optional, set by main to report status)
	OnStatus   StatusFunc   `json:"-"`
	OnProgress ProgressFunc `json:"-"`
}

// OrgPosture represents the collected security posture of a GitHub organization.
// The audit/internal surface fields are nil at trust (omitempty), so a trust
// run emits only the aggregate fields.
type OrgPosture struct {
	SchemaVersion         string                `json:"schema_version"`
	CollectedAt           string                `json:"collected_at"`
	CollectedAtLevel      string                `json:"collected_at_level"`
	Organization          string                `json:"organization"`
	Scope                 Scope                 `json:"scope"`
	Posture               Posture               `json:"posture"`
	AccessControl         AccessControl         `json:"access_control"`
	BranchProtectionRules BranchProtectionRules `json:"branch_protection_rules"`
	SecurityFeatures      SecurityFeatures      `json:"security_features"`

	// Audit / internal surfaces (nil at trust; omitempty keeps trust stable).
	Members      *Members      `json:"members,omitempty"`
	Repositories *Repositories `json:"repositories,omitempty"`
	Codeowners   *Codeowners   `json:"codeowners,omitempty"`
	Webhooks     *Webhooks     `json:"webhooks,omitempty"`
	DeployKeys   *DeployKeys   `json:"deploy_keys,omitempty"`
	Actions      *Actions      `json:"actions,omitempty"`
	AuditLog     *AuditLog     `json:"audit_log,omitempty"`
	Apps         *Apps         `json:"apps,omitempty"`
	Tokens       *Tokens       `json:"tokens,omitempty"`

	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`
}

// Diagnostics contains warnings and errors encountered during collection.
// This helps identify permission issues vs features that are genuinely disabled.
type Diagnostics struct {
	PermissionErrors []string `json:"permission_errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// Scope describes what was included and excluded from collection.
type Scope struct {
	IncludePatterns      []string `json:"include_patterns"`
	ExcludePatterns      []string `json:"exclude_patterns"`
	RepositoriesCoverage int      `json:"repositories_coverage"`
}

// Posture contains high-level posture coverage metrics.
type Posture struct {
	BranchProtectionCoverage int `json:"branch_protection_coverage"`
	SecurityFeaturesCoverage int `json:"security_features_coverage"`
}

// AccessControl contains organization-level access control posture.
// TwoFactorRequired is a pointer to distinguish between "false" and "unknown" (nil = insufficient permissions).
// The audit-level fields below populate only at audit and above (omitempty).
type AccessControl struct {
	TwoFactorRequired *bool `json:"two_factor_required"`

	// Audit-level org access-control settings (from GET /orgs/{org}).
	DefaultRepositoryPermission  string `json:"default_repository_permission,omitempty"`
	MembersCanCreateRepositories *bool  `json:"members_can_create_repositories,omitempty"`
}

// BranchProtectionRules contains per-rule coverage percentages.
type BranchProtectionRules struct {
	PullRequestRequired int `json:"pull_request_required"`
	ApprovingReviews    int `json:"approving_reviews"`
	DismissStaleReviews int `json:"dismiss_stale_reviews"`
	CodeOwnerReviews    int `json:"code_owner_reviews"`
	StatusChecks        int `json:"status_checks"`
	SignedCommits       int `json:"signed_commits"`
	AdminEnforcement    int `json:"admin_enforcement"`
}

// SecurityFeatures contains per-feature coverage percentages (trust) plus
// per-repo rows (audit) and a findings inventory (internal).
type SecurityFeatures struct {
	VulnerabilityAlerts          int `json:"vulnerability_alerts"`
	CodeScanning                 int `json:"code_scanning"`
	SecretScanning               int `json:"secret_scanning"`
	SecretScanningPushProtection int `json:"secret_scanning_push_protection"`
	DependabotSecurityUpdates    int `json:"dependabot_security_updates"`

	// Audit-level per-repo feature flags + open-alert counts.
	PerRepo []SecurityFeaturesRow `json:"per_repo,omitempty"`
	// Internal-level findings inventories.
	Findings *SecurityFindings `json:"findings,omitempty"`
}

// SecurityFeaturesRow is the per-repo audit-level view: the booleans behind the
// trust percentages plus open-alert counts by type.
type SecurityFeaturesRow struct {
	Repository                   string `json:"repository"`
	VulnerabilityAlerts          bool   `json:"vulnerability_alerts"`
	CodeScanning                 bool   `json:"code_scanning"`
	SecretScanning               bool   `json:"secret_scanning"`
	SecretScanningPushProtection bool   `json:"secret_scanning_push_protection"`
	DependabotSecurityUpdates    bool   `json:"dependabot_security_updates"`
	OpenSecretScanningAlerts     int    `json:"open_secret_scanning_alerts"`
	OpenCodeScanningAlerts       int    `json:"open_code_scanning_alerts"`
	OpenDependabotAlerts         int    `json:"open_dependabot_alerts"`
}

// --- Audit / internal surfaces ---
//
// These populate only at audit and above; at trust they stay nil, so a trust
// run emits only aggregates and needs no extra permissions.

// Members is the org member inventory (audit+).
type Members struct {
	MemberCount              int         `json:"member_count"`
	AdminCount               int         `json:"admin_count"`
	OutsideCollaboratorCount int         `json:"outside_collaborator_count"`
	HasPendingInvitations    bool        `json:"has_pending_invitations"`
	PerMember                []MemberRow `json:"per_member,omitempty"`
	Truncated                bool        `json:"truncated,omitempty"`
	TruncatedDropped         int         `json:"truncated_dropped,omitempty"`
}

// MemberRow is one member. TwoFactorEnabled is a pointer: nil means the 2FA
// signal was unavailable (caller not an org owner), not "2FA off".
//
// Name is the public-profile display name. Other collectors emit logins only,
// but GitHub logins are pseudonyms that reviewers cannot map to people, and
// the display name is already world-readable on github.com, unlike IdP
// profile attributes. Empty when the member has not set one.
type MemberRow struct {
	Login            string `json:"login"`
	Name             string `json:"name,omitempty"`
	Role             string `json:"role"`
	TwoFactorEnabled *bool  `json:"two_factor_enabled,omitempty"`
	LastActivity     string `json:"last_activity,omitempty"`
}

// Repositories is the repo inventory (audit+).
type Repositories struct {
	TotalCount       int       `json:"total_count"`
	PublicCount      int       `json:"public_count"`
	PrivateCount     int       `json:"private_count"`
	InternalCount    int       `json:"internal_count"`
	ArchivedCount    int       `json:"archived_count"`
	DefaultProtected int       `json:"default_branch_protected_count"`
	PerRepo          []RepoRow `json:"per_repo,omitempty"`
	Truncated        bool      `json:"truncated,omitempty"`
	TruncatedDropped int       `json:"truncated_dropped,omitempty"`
}

// RepoRow is one repository's inventory + branch-protection detail.
type RepoRow struct {
	Name             string                  `json:"name"`
	Visibility       string                  `json:"visibility"`
	Archived         bool                    `json:"archived"`
	IsTemplate       bool                    `json:"is_template"`
	DefaultBranch    string                  `json:"default_branch,omitempty"`
	CreatedAt        string                  `json:"created_at,omitempty"`
	UpdatedAt        string                  `json:"updated_at,omitempty"`
	PushedAt         string                  `json:"pushed_at,omitempty"`
	PrimaryLanguage  string                  `json:"primary_language,omitempty"`
	SizeKB           int                     `json:"size_kb,omitempty"`
	BranchProtection *BranchProtectionDetail `json:"branch_protection,omitempty"`

	// Internal-only low-sensitivity metadata.
	Description    string   `json:"description,omitempty"`
	Topics         []string `json:"topics,omitempty"`
	LicenseSPDX    string   `json:"license_spdx,omitempty"`
	StargazerCount int      `json:"stargazer_count,omitempty"`
}

// BranchProtectionDetail is the default-branch protection rule, per repo.
type BranchProtectionDetail struct {
	RequiresApprovingReviews       bool `json:"requires_approving_reviews"`
	RequiredApprovingReviewCount   int  `json:"required_approving_review_count"`
	DismissesStaleReviews          bool `json:"dismisses_stale_reviews"`
	RequiresCodeOwnerReviews       bool `json:"requires_code_owner_reviews"`
	RequiresStatusChecks           bool `json:"requires_status_checks"`
	RequiresCommitSignatures       bool `json:"requires_commit_signatures"`
	IsAdminEnforced                bool `json:"is_admin_enforced"`
	RequiresLinearHistory          bool `json:"requires_linear_history"`
	AllowsForcePushes              bool `json:"allows_force_pushes"`
	AllowsDeletions                bool `json:"allows_deletions"`
	RequiresConversationResolution bool `json:"requires_conversation_resolution"`
}

// Codeowners reports CODEOWNERS presence (audit) and content hash (internal).
type Codeowners struct {
	PerRepo []CodeownersRow `json:"per_repo,omitempty"`
}

// CodeownersRow is one repo's CODEOWNERS status. The file contents are never
// emitted; Hash is a SHA-256 computed in-process at internal level.
type CodeownersRow struct {
	Repository string `json:"repository"`
	Present    bool   `json:"present"`
	Path       string `json:"path,omitempty"`
	Hash       string `json:"hash,omitempty"`
}

// Webhooks is the org + repo webhook inventory (audit counts, internal detail).
type Webhooks struct {
	OrgCount     int            `json:"org_count"`
	RepoCount    int            `json:"repo_count"`
	CountByEvent map[string]int `json:"count_by_event,omitempty"`
	Org          []WebhookRow   `json:"org,omitempty"`
	Repo         []WebhookRow   `json:"repo,omitempty"`
	Truncated    bool           `json:"truncated,omitempty"`
}

// WebhookRow is one webhook. Only the URL host is emitted (never path/query/secret).
type WebhookRow struct {
	Repository         string   `json:"repository,omitempty"`
	ID                 int64    `json:"id"`
	Active             bool     `json:"active"`
	ContentType        string   `json:"content_type,omitempty"`
	Events             []string `json:"events,omitempty"`
	URLHost            string   `json:"url_host,omitempty"`
	LastResponseCode   int      `json:"last_response_code,omitempty"`
	LastResponseStatus string   `json:"last_response_status,omitempty"`
}

// DeployKeys is the per-repo deploy-key inventory (audit counts, internal detail).
type DeployKeys struct {
	TotalCount     int            `json:"total_count"`
	ReadWriteCount int            `json:"read_write_count"`
	PerKey         []DeployKeyRow `json:"per_key,omitempty"`
}

// DeployKeyRow is one deploy key. The public key is fingerprinted, not emitted.
type DeployKeyRow struct {
	Repository  string `json:"repository"`
	ID          int64  `json:"id"`
	Title       string `json:"title,omitempty"`
	ReadOnly    bool   `json:"read_only"`
	CreatedAt   string `json:"created_at,omitempty"`
	LastUsed    string `json:"last_used,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Actions is the Actions runners/secrets/workflows surface (audit+).
type Actions struct {
	OrgRunnerCount  int         `json:"org_runner_count"`
	RepoRunnerCount int         `json:"repo_runner_count"`
	OrgSecretCount  int         `json:"org_secret_count"`
	OrgRunners      []RunnerRow `json:"org_runners,omitempty"`
	RepoRunners     []RunnerRow `json:"repo_runners,omitempty"`
	OrgSecretNames  []string    `json:"org_secret_names,omitempty"`
}

// RunnerRow is one self-hosted runner.
type RunnerRow struct {
	Repository string   `json:"repository,omitempty"`
	ID         int64    `json:"id"`
	Name       string   `json:"name,omitempty"`
	OS         string   `json:"os,omitempty"`
	Status     string   `json:"status,omitempty"`
	Busy       bool     `json:"busy"`
	Labels     []string `json:"labels,omitempty"`
}

// AuditLog is the security-relevant audit-log surface (audit counts, internal
// events). Enterprise Cloud only; degrades to a diagnostic otherwise.
type AuditLog struct {
	WindowDays       int            `json:"window_days"`
	CountByCategory  map[string]int `json:"count_by_category,omitempty"`
	Events           []AuditLogRow  `json:"events,omitempty"`
	Truncated        bool           `json:"truncated,omitempty"`
	TruncatedDropped int            `json:"truncated_dropped,omitempty"`
}

// AuditLogRow is one audit event (metadata only, no payload bodies).
type AuditLogRow struct {
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// Apps is the installed-GitHub-App inventory (audit+).
type Apps struct {
	InstallationCount int      `json:"installation_count"`
	PerInstallation   []AppRow `json:"per_installation,omitempty"`
}

// AppRow is one installed App.
type AppRow struct {
	AppSlug             string            `json:"app_slug,omitempty"`
	AppID               int64             `json:"app_id"`
	Suspended           bool              `json:"suspended"`
	Permissions         map[string]string `json:"permissions,omitempty"`
	CreatedAt           string            `json:"created_at,omitempty"`
	UpdatedAt           string            `json:"updated_at,omitempty"`
	RepositorySelection string            `json:"repository_selection,omitempty"`
	Events              []string          `json:"events,omitempty"`
}

// Tokens is the PAT / fine-grained-token surface (audit count, internal detail).
// Enterprise / FGT-policy orgs only; degrades to a diagnostic otherwise.
type Tokens struct {
	GrantCount int        `json:"grant_count"`
	PerToken   []TokenRow `json:"per_token,omitempty"`
}

// TokenRow is one fine-grained PAT grant. Token values are never emitted.
type TokenRow struct {
	ID          int64    `json:"id"`
	Owner       string   `json:"owner,omitempty"`
	TokenName   string   `json:"token_name,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	LastUsed    string   `json:"last_used,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// NewOrgPosture creates a new OrgPosture with the current timestamp.
func NewOrgPosture(org string) *OrgPosture {
	return &OrgPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		Organization:  org,
	}
}
