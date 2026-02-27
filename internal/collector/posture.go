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
type OrgPosture struct {
	SchemaVersion         string                `json:"schema_version"`
	CollectedAt           string                `json:"collected_at"`
	Organization          string                `json:"organization"`
	Scope                 Scope                 `json:"scope"`
	Posture               Posture               `json:"posture"`
	AccessControl         AccessControl         `json:"access_control"`
	BranchProtectionRules BranchProtectionRules `json:"branch_protection_rules"`
	SecurityFeatures      SecurityFeatures      `json:"security_features"`
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
type AccessControl struct {
	TwoFactorRequired *bool `json:"two_factor_required"`
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

// SecurityFeatures contains per-feature coverage percentages.
type SecurityFeatures struct {
	VulnerabilityAlerts          int `json:"vulnerability_alerts"`
	CodeScanning                 int `json:"code_scanning"`
	SecretScanning               int `json:"secret_scanning"`
	SecretScanningPushProtection int `json:"secret_scanning_push_protection"`
	DependabotSecurityUpdates    int `json:"dependabot_security_updates"`
}

// NewOrgPosture creates a new OrgPosture with the current timestamp.
func NewOrgPosture(org string) *OrgPosture {
	return &OrgPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		Organization:  org,
	}
}
