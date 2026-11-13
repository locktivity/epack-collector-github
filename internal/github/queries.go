// Package github provides the GitHub REST and GraphQL calls the collector makes.
package github

import (
	"cmp"
	"encoding/json"
	"time"
)

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

// The repositories query's fields, by whether GitHub's GraphQL schema lets
// them be null. GraphQL answers every field a query selects.
var (
	repositoryNonNull  = []string{"name", "owner/login", "isArchived", "isTemplate", "visibility", "hasVulnerabilityAlertsEnabled", "stargazerCount"}
	repositoryNullable = []string{"defaultBranchRef", "diskUsage"}
	protectionNonNull  = []string{
		"requiresApprovingReviews", "dismissesStaleReviews", "requiresCodeOwnerReviews", "requiresStatusChecks", "requiresCommitSignatures",
		"isAdminEnforced", "requiresLinearHistory", "allowsForcePushes", "allowsDeletions", "requiresConversationResolution",
	}
)

// checkRepositoryNode returns an invalid_response error for a node of the
// repositories query that leaves out a field the collector reads, or holds
// null in one GitHub's schema makes non-null, such as isAdminEnforced. Read
// as it stands, such a node would turn a missing setting into false.
func checkRepositoryNode(raw json.RawMessage) error {
	var node map[string]any
	if err := json.Unmarshal(raw, &node); err != nil {
		return invalidResponse("graphql repositories response lists a repository that is not an object")
	}
	field := cmp.Or(missingField(node, false, repositoryNonNull...), missingField(node, true, repositoryNullable...))
	ref, _ := node["defaultBranchRef"].(map[string]any)
	if field == "" && ref != nil {
		field = cmp.Or(missingField(node, false, "defaultBranchRef/name"), missingField(node, true, "defaultBranchRef/branchProtectionRule"))
	}
	if rule, _ := ref["branchProtectionRule"].(map[string]any); field == "" && rule != nil {
		field = missingField(rule, false, protectionNonNull...)
		if field == "" {
			field = missingField(rule, true, "requiredApprovingReviewCount")
		}
		if field != "" {
			field = "defaultBranchRef/branchProtectionRule/" + field
		}
	}
	if field != "" {
		return invalidResponse("graphql repositories response lists a repository with no %s", field)
	}
	return nil
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
	CreatedAt time.Time
	UpdatedAt time.Time
	PushedAt  time.Time
	// DiskUsage is nil when GitHub reports none.
	DiskUsage       *int
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
