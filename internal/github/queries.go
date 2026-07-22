// Package github provides GraphQL client functionality for GitHub API.
package github

import "github.com/shurcooL/githubv4"

// RepositoriesQuery is the GraphQL query for fetching organization repositories
// with branch protection and security feature information.
type RepositoriesQuery struct {
	Organization struct {
		Repositories struct {
			Nodes    []Repository
			PageInfo struct {
				HasNextPage bool
				EndCursor   githubv4.String
			}
		} `graphql:"repositories(first: 100, after: $cursor)"`
	} `graphql:"organization(login: $org)"`
}

// Repository represents a GitHub repository with security-relevant fields.
// The inventory fields (timestamps, language, size, etc.) are used only by the
// audit/internal Repositories surface; trust collection ignores them.
type Repository struct {
	Name  string
	Owner struct {
		Login string
	}
	IsArchived       bool
	IsTemplate       bool
	Visibility       string // PUBLIC, PRIVATE, INTERNAL
	DefaultBranchRef struct {
		Name                 string
		BranchProtectionRule *BranchProtectionRule
	}
	HasVulnerabilityAlertsEnabled bool

	// Inventory metadata (audit / internal).
	CreatedAt       githubv4.DateTime
	UpdatedAt       githubv4.DateTime
	PushedAt        githubv4.DateTime
	DiskUsage       int
	StargazerCount  int
	Description     string
	PrimaryLanguage *struct {
		Name string
	}
	LicenseInfo *struct {
		SpdxID string `graphql:"spdxId"`
	}
	RepositoryTopics struct {
		Nodes []struct {
			Topic struct {
				Name string
			}
		}
	} `graphql:"repositoryTopics(first: 20)"`
}

// MembersWithRoleQuery is the GraphQL query for fetching member display
// names, which GitHub's REST member list endpoints do not return.
type MembersWithRoleQuery struct {
	Organization struct {
		MembersWithRole struct {
			Nodes []struct {
				Login string
				Name  string
			}
			PageInfo struct {
				HasNextPage bool
				EndCursor   githubv4.String
			}
		} `graphql:"membersWithRole(first: 100, after: $cursor)"`
	} `graphql:"organization(login: $org)"`
}

// BranchProtectionRule represents branch protection settings.
type BranchProtectionRule struct {
	RequiresApprovingReviews       bool
	RequiredApprovingReviewCount   int
	DismissesStaleReviews          bool
	RequiresCodeOwnerReviews       bool
	RequiresStatusChecks           bool
	RequiresCommitSignatures       bool
	IsAdminEnforced                bool
	RequiresLinearHistory          bool
	AllowsForcePushes              bool
	AllowsDeletions                bool
	RequiresConversationResolution bool
}
