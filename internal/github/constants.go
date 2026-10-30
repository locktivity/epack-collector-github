package github

// API configuration.
const (
	DefaultBaseURL    = "https://api.github.com"
	DefaultGraphQLURL = "https://api.github.com/graphql"
	AcceptHeader      = "application/vnd.github+json"
	APIVersion        = "2022-11-28"
)

// APIHost is the only host the collector sends credentials to.
const APIHost = "api.github.com"

// installationTokenPrefix is the prefix of every GitHub App installation token.
const installationTokenPrefix = "ghs_"

// Security status values.
const (
	StatusEnabled   = "enabled"
	StateConfigured = "configured"
)
