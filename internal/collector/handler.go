package collector

import (
	"time"

	"github.com/locktivity/epack-collector-github/docs/schema"
	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        "github",
		Version:     version,
		Commit:      commit,
		Description: "Collects GitHub organization security posture metrics",
		Schemas:     map[string][]byte{DetailedPath: schema.Detailed},
		TraceMap:    schema.TraceMap,
		Timeout:     30 * time.Minute,
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := Config{
		Organization:    getString(cfg, "organization"),
		GitHubToken:     ctx.Secret("GITHUB_TOKEN"),
		AppID:           getInt64(cfg, "app_id"),
		InstallationID:  getInt64(cfg, "installation_id"),
		PrivateKey:      ctx.Secret("GITHUB_APP_PRIVATE_KEY"),
		IncludePatterns: getStringSlice(cfg, "include_patterns"),
		ExcludePatterns: getStringSlice(cfg, "exclude_patterns"),
		OnStatus:        ctx.Status,
		OnProgress:      ctx.Progress,
		Recorder:        componentsdk.Records(ctx),
		Now:             func() time.Time { return componentsdk.Now(ctx) },
	}

	if config.Organization == "" {
		return componentsdk.NewConfigError("organization is required")
	}
	hasAppAuth := config.AppID != 0 && config.PrivateKey != ""
	if !hasAppAuth && config.GitHubToken == "" {
		return componentsdk.NewConfigError("authentication required: provide GITHUB_TOKEN or app_id + GITHUB_APP_PRIVATE_KEY")
	}

	config.Transport = componentsdk.NewTransport(ctx, componentsdk.HTTPOptions{
		CredentialHosts: []string{github.APIHost},
		NameOperation:   github.NameOperation,
		TemplateRoute:   github.TemplateRoute,
	})
	c, err := New(config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}
	posture, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return err
	}
	return ctx.Emit(posture.Artifacts())
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
