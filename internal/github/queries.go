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
type Repository struct {
	Name  string
	Owner struct {
		Login string
	}
	Visibility       string // PUBLIC, PRIVATE, INTERNAL
	DefaultBranchRef struct {
		Name                 string
		BranchProtectionRule *BranchProtectionRule
	}
	HasVulnerabilityAlertsEnabled bool
}

// BranchProtectionRule represents branch protection settings.
type BranchProtectionRule struct {
	RequiresApprovingReviews     bool
	RequiredApprovingReviewCount int
	DismissesStaleReviews        bool
	RequiresCodeOwnerReviews     bool
	RequiresStatusChecks         bool
	RequiresCommitSignatures     bool
	IsAdminEnforced              bool
}
