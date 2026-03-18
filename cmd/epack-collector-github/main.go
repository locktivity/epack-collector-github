// epack-collector-github collects GitHub organization security posture.
//
// This binary is designed to be executed by the epack collector runner.
// It uses the epack Component SDK for protocol compliance.
package main

import (
	"github.com/locktivity/epack-collector-github/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

// Build-time variables set via -ldflags
var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "github",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects GitHub organization security posture metrics",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	// Build config from SDK context
	cfg := ctx.Config()
	config := collector.Config{
		Organization:    getString(cfg, "organization"),
		GitHubToken:     ctx.Secret("GITHUB_TOKEN"),
		AppID:           getInt64(cfg, "app_id"),
		InstallationID:  getInt64(cfg, "installation_id"),
		PrivateKey:      ctx.Secret("GITHUB_APP_PRIVATE_KEY"),
		IncludePatterns: getStringSlice(cfg, "include_patterns"),
		ExcludePatterns: getStringSlice(cfg, "exclude_patterns"),
		OnStatus:        ctx.Status,
		OnProgress:      ctx.Progress,
	}

	if config.Organization == "" {
		return componentsdk.NewConfigError("organization is required")
	}

	// Check for valid auth configuration
	hasAppAuth := config.AppID != 0 && config.PrivateKey != ""
	hasTokenAuth := config.GitHubToken != ""
	if !hasAppAuth && !hasTokenAuth {
		return componentsdk.NewConfigError("authentication required: provide GITHUB_TOKEN or app_id + GITHUB_APP_PRIVATE_KEY")
	}

	// Create collector and collect posture
	c, err := collector.New(config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}
	posture, err := c.Collect(ctx.Context())
	if err != nil {
		return componentsdk.NewNetworkError("collecting posture: %v", err)
	}

	// Transform to normalized vcs-posture format
	normalized := posture.ToVCSPosture()

	// Emit both detailed and normalized artifacts
	return ctx.Emit([]componentsdk.CollectedArtifact{
		{
			// Detailed GitHub-specific output
			Data: posture,
			Path: "artifacts/github.json",
		},
		{
			// Normalized VCS posture for profile evaluation
			Data:   normalized,
			Schema: "evidencepack/vcs-posture@v1",
			Path:   "artifacts/github.vcs-posture.json",
		},
	})
}

// getString safely extracts a string from config map
func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

// getInt64 safely extracts an int64 from config map
func getInt64(cfg map[string]any, key string) int64 {
	if cfg == nil {
		return 0
	}
	switch v := cfg[key].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	}
	return 0
}

// getStringSlice safely extracts a string slice from config map
func getStringSlice(cfg map[string]any, key string) []string {
	if cfg == nil {
		return nil
	}
	if v, ok := cfg[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
