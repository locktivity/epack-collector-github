package collector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/locktivity/epack-collector-github/internal/github"
	"github.com/locktivity/epack/componentsdk"
)

// GitHub App permissions, by their keys in an installation's permissions.
// Fine-grained tokens use the same permissions.
const (
	permActions                 = "actions"
	permAdministration          = "administration"
	permContents                = "contents"
	permDependabotAlerts        = "vulnerability_alerts"
	permMembers                 = "members"
	permMetadata                = "metadata"
	permOrgAdministration       = "organization_administration"
	permOrgHooks                = "organization_hooks"
	permOrgPersonalAccessTokens = "organization_personal_access_tokens"
	permOrgSecrets              = "organization_secrets"
	permOrgSelfHostedRunners    = "organization_self_hosted_runners"
	permRepoHooks               = "repository_hooks"
	permSecretScanningAlerts    = "secret_scanning_alerts"
	permSecurityEvents          = "security_events"
)

// operationPermissions is the permission each call needs, at read access, as
// GitHub lists the permissions each endpoint requires.
var operationPermissions = map[string]string{
	"github.repositories.list":                 permMetadata,
	"github.installation_repositories.list":    permMetadata,
	"github.branch_rules.list":                 permMetadata,
	"github.rulesets.get":                      permMetadata,
	"github.repos.get":                         permMetadata,
	"github.code_scanning_default_setup.get":   permAdministration,
	"github.code_scanning_analyses.list":       permSecurityEvents,
	"github.org_settings.get":                  permOrgAdministration,
	"github.secret_scanning_alerts.list":       permSecretScanningAlerts,
	"github.code_scanning_alerts.list":         permSecurityEvents,
	"github.dependabot_alerts.list":            permDependabotAlerts,
	"github.repo_contents.get":                 permContents,
	"github.org_hooks.list":                    permOrgHooks,
	"github.repo_hooks.list":                   permRepoHooks,
	"github.deploy_keys.list":                  permAdministration,
	"github.org_runners.list":                  permOrgSelfHostedRunners,
	"github.org_actions_secrets.list":          permOrgSecrets,
	"github.repo_runners.list":                 permAdministration,
	"github.environments.list":                 permActions,
	"github.environment_branch_policies.list":  permActions,
	"github.environment_protection_rules.list": permActions,
	"github.audit_log.list":                    permOrgAdministration,
	"github.org_installations.list":            permOrgAdministration,
	"github.org_personal_access_tokens.list":   permOrgPersonalAccessTokens,
	"github.org_members.list":                  permMembers,
	"github.member_names.list":                 permMembers,
	"github.org_admins.list":                   permMembers,
	"github.outside_collaborators.list":        permMembers,
	"github.org_members_2fa_disabled.list":     permMembers,
	"github.org_invitations.list":              permMembers,
}

// withheldPermissions is the permission without which GitHub leaves each of
// these values out of a response it answers.
var withheldPermissions = []struct {
	err        error
	permission string
}{
	{errTwoFactorHidden, permOrgAdministration},
	{errRepositoryCountHidden, permOrgAdministration},
	{errOrgSettingsHidden, permOrgAdministration},
	{github.ErrAnalysisHidden, permAdministration},
}

// neededPermission returns the permission a denial in err's chain calls for,
// or "" when err is no denial the collector can name a permission for.
// withheld reports a value GitHub left out of a response rather than a call
// it refused.
func neededPermission(err error) (permission string, withheld bool) {
	for _, w := range withheldPermissions {
		if errors.Is(err, w.err) {
			return w.permission, true
		}
	}
	var apiErr *github.APIError
	if isDenied(err) && errors.As(err, &apiErr) {
		return operationPermissions[apiErr.Operation], false
	}
	return "", false
}

// permissionOptions returns the warning for a gap that err, a denial, left,
// and the permission to grant when the GitHub App signed in without it. A
// token's permissions cannot be read, so its gaps name none. A call refused
// with the permission granted gets a warning that something else refused
// it, but a withheld value needs none: its error says what GitHub asks for.
func permissionOptions(err error, credential *github.Credential) []componentsdk.GapOption {
	permission, withheld := neededPermission(err)
	if permission == "" || credential == nil {
		return nil
	}
	need := permission + ":read"
	switch credential.Kind {
	case github.CredentialAppInstallation:
		if granted := grantedScope(credential.Scopes, permission); granted != "" {
			if withheld {
				return nil
			}
			return []componentsdk.GapOption{componentsdk.Warning(fmt.Sprintf("GitHub refused this although the GitHub App has %s.", granted))}
		}
		return []componentsdk.GapOption{
			componentsdk.Warning(fmt.Sprintf("Grant the GitHub App %s.", need)),
			componentsdk.MissingPermission(need),
		}
	case github.CredentialToken:
		return []componentsdk.GapOption{componentsdk.Warning(fmt.Sprintf("A GitHub App or fine-grained token needs %s for this.", need))}
	}
	return nil
}

// grantedScope returns the installation scope that grants permission at any
// access level, as name:level, or "".
func grantedScope(scopes []string, permission string) string {
	for _, s := range scopes {
		if name, _, _ := strings.Cut(s, ":"); name == permission {
			return s
		}
	}
	return ""
}
