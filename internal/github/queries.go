// Package github provides the GitHub REST and GraphQL calls the collector makes.
package github

import "time"

// repositoriesQuery fetches an organization's repositories with branch
// protection and security feature information, 100 per page.
const repositoriesQuery = `query($cursor:String$org:String!){organization(login: $org){repositories(first: 100, after: $cursor){nodes{name,owner{login},isArchived,isTemplate,visibility,defaultBranchRef{name,branchProtectionRule{requiresApprovingReviews,requiredApprovingReviewCount,dismissesStaleReviews,requiresCodeOwnerReviews,requiresStatusChecks,requiresCommitSignatures,isAdminEnforced,requiresLinearHistory,allowsForcePushes,allowsDeletions,requiresConversationResolution}},hasVulnerabilityAlertsEnabled,createdAt,updatedAt,pushedAt,diskUsage,stargazerCount,description,primaryLanguage{name},licenseInfo{spdxId},repositoryTopics(first: 20){nodes{topic{name}}}},pageInfo{hasNextPage,endCursor}}}}`

// membersQuery fetches member display names, which GitHub's REST member list
// endpoints do not return, 100 per page.
const membersQuery = `query($cursor:String$org:String!){organization(login: $org){membersWithRole(first: 100, after: $cursor){nodes{login,name},pageInfo{hasNextPage,endCursor}}}}`

type pageInfo struct {
	HasNextPage bool
	EndCursor   string
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
	CreatedAt       time.Time
	UpdatedAt       time.Time
	PushedAt        time.Time
	DiskUsage       int
	StargazerCount  int
	Description     string
	PrimaryLanguage *struct {
		Name string
	}
	LicenseInfo *struct {
		SpdxID string
	}
	RepositoryTopics struct {
		Nodes []struct {
			Topic struct {
				Name string
			}
		}
	}
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
