package github

import (
	"net/http"
	"strings"
	"sync"

	"github.com/locktivity/epack/componentsdk"
)

// GitHub App permissions, by their keys in an installation's permissions.
// Fine-grained tokens use the same permissions.
const (
	PermActions                 = "actions"
	PermAdministration          = "administration"
	PermContents                = "contents"
	PermDependabotAlerts        = "vulnerability_alerts"
	PermMembers                 = "members"
	PermMetadata                = "metadata"
	PermOrgAdministration       = "organization_administration"
	PermOrgHooks                = "organization_hooks"
	PermOrgPersonalAccessTokens = "organization_personal_access_tokens"
	PermOrgSecrets              = "organization_secrets"
	PermOrgSelfHostedRunners    = "organization_self_hosted_runners"
	PermRepoHooks               = "repository_hooks"
	PermSecretScanningAlerts    = "secret_scanning_alerts"
	PermSecurityEvents          = "security_events"
)

// OperationPermissions is the permission each call needs, at read access,
// as GitHub lists the permissions each endpoint requires. The sign-in, the
// organization read, and the public profile read need none.
var OperationPermissions = map[string]string{
	"github.repositories.list":                       PermMetadata,
	"github.installation_repositories.list":          PermMetadata,
	"github.branch_rules.list":                       PermMetadata,
	"github.rulesets.get":                            PermMetadata,
	"github.repos.get":                               PermMetadata,
	"github.code_scanning_default_setup.get":         PermAdministration,
	"github.code_scanning_analyses.list":             PermSecurityEvents,
	"github.org_settings.get":                        PermOrgAdministration,
	"github.secret_scanning_alerts.list":             PermSecretScanningAlerts,
	"github.code_scanning_alerts.list":               PermSecurityEvents,
	"github.dependabot_alerts.list":                  PermDependabotAlerts,
	"github.repo_contents.get":                       PermContents,
	"github.org_hooks.list":                          PermOrgHooks,
	"github.repo_hooks.list":                         PermRepoHooks,
	"github.deploy_keys.list":                        PermAdministration,
	"github.org_runners.list":                        PermOrgSelfHostedRunners,
	"github.org_actions_secrets.list":                PermOrgSecrets,
	"github.repo_runners.list":                       PermAdministration,
	"github.environments.list":                       PermActions,
	"github.environment_branch_policies.list":        PermActions,
	"github.environment_protection_rules.list":       PermActions,
	"github.audit_log.list":                          PermOrgAdministration,
	"github.org_installations.list":                  PermOrgAdministration,
	"github.org_personal_access_tokens.list":         PermOrgPersonalAccessTokens,
	"github.org_members.list":                        PermMembers,
	"github.member_names.list":                       PermMembers,
	"github.org_admins.list":                         PermMembers,
	"github.outside_collaborators.list":              PermMembers,
	"github.org_members_2fa_disabled.list":           PermMembers,
	"github.outside_collaborators_2fa_disabled.list": PermMembers,
	"github.org_invitations.list":                    PermMembers,
	"github.saml_identities.list":                    PermMembers,
}

// ReadPermission is the permission the call named op needs, as name:read,
// such as members:read. It is "" for a call that needs none.
func ReadPermission(op string) string {
	if p, ok := OperationPermissions[op]; ok {
		return p + ":read"
	}
	return ""
}

// GrantedScope returns the scope in scopes, each as name:level, that grants
// permission at any access level, or "".
func GrantedScope(scopes []string, permission string) string {
	for _, s := range scopes {
		if name, _, _ := strings.Cut(s, ":"); name == permission {
			return s
		}
	}
	return ""
}

// Grants holds the permissions of the credential the run signed in with,
// for componentsdk.HTTPOptions.NamesPermission. A denied call's permission
// goes in its gap as missing only when the run signed in as a GitHub App
// that lacks it. A token's permissions cannot be read. Granting a GitHub App
// a permission it already holds would not lift the denial.
type Grants struct {
	mu     sync.Mutex
	app    bool
	scopes []string
}

// SignedIn records the credential the run signed in with.
func (g *Grants) SignedIn(c Credential) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.app = c.Kind == CredentialAppInstallation
	g.scopes = append([]string(nil), c.Scopes...)
}

// NamesPermission is the componentsdk.HTTPOptions.NamesPermission hook. It
// reports whether the GitHub App the run signed in as lacks the permission
// of the denied call that resp answered.
func (g *Grants) NamesPermission(resp *http.Response, _ []byte) bool {
	if resp == nil || resp.Request == nil {
		return false
	}
	op, _ := componentsdk.OperationOf(resp.Request.Context())
	name, _, _ := strings.Cut(op.Permission, ":")
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.app && name != "" && GrantedScope(g.scopes, name) == ""
}
