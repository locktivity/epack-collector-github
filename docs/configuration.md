# Configuration

## Authentication

The collector supports two authentication methods. **GitHub App is recommended** for manual setups because it provides better security and audit capabilities. For managed or brokered runtimes, the collector can also consume a short-lived `GITHUB_TOKEN`.

### GitHub App (Recommended)

GitHub Apps provide the best security posture:
- Not tied to a user account
- Better audit logging
- Higher rate limits
- Recommended by GitHub for org-level integrations

```yaml
collectors:
  github:
    source: locktivity/epack-collector-github@^0.1
    config:
      organization: myorg
      app_id: 123456
      installation_id: 78901234
    secrets:
      - GITHUB_APP_PRIVATE_KEY
```

#### Creating a GitHub App

1. Go to your organization's **Settings > Developer settings > GitHub Apps > New GitHub App**
2. Set the following:
   - **GitHub App name**: `epack-posture-collector` (or your preferred name)
   - **Homepage URL**: Your organization's URL
   - **Webhook**: Uncheck "Active" (not needed)
3. Set **Permissions**:
   - **Repository permissions**:
     - Administration: Read-only
     - Code scanning alerts: Read-only
     - Contents: Read-only
     - Dependabot alerts: Read-only
     - Metadata: Read-only
   - **Organization permissions**:
     - Administration: Read-only
     - Members: Read-only
     - Personal access tokens: Read-only
4. Set **Where can this GitHub App be installed?** to "Only on this account"
5. Click **Create GitHub App**
6. Note the **App ID** from the app settings page
7. Scroll down and click **Generate a private key** - save the `.pem` file
8. Click **Install App** and install it on your organization
9. Note the **Installation ID** from the URL (e.g., `https://github.com/organizations/myorg/settings/installations/78901234`)

#### Providing the Private Key

Set the `GITHUB_APP_PRIVATE_KEY` secret to the contents of the `.pem` file:

```bash
export GITHUB_APP_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
epack collect
```

### `GITHUB_TOKEN` (Brokered Token or PAT)

The collector accepts a `GITHUB_TOKEN` for GitHub API access. In practice this can be:
- a short-lived GitHub installation token injected by a trusted runtime or broker
- a classic PAT for manual setups

Classic PATs still work, but they are not recommended when a short-lived or GitHub App-based flow is available.

The collector recognizes an installation token by its `ghs_` prefix and applies the installation's [repository selection](#selected-repositories). The result's `signed_in_as.kind` is `installation_token`. GitHub does not show the token's permissions, so `signed_in_as.scopes` is empty and gaps do not set `missing_permission`.

```yaml
collectors:
  github:
    source: locktivity/epack-collector-github@^0.1
    config:
      organization: myorg
    secrets:
      - GITHUB_TOKEN
```

Create a classic token with these scopes:
- `repo` - Repository access (or `public_repo` for public repos only)
- `read:org` - Members, owners, and SAML single sign-on
- `admin:org` - (Optional) Read organization settings for 2FA status

**Note:** Without `admin:org`, the collector will still work but `two_factor_required` will be `null` (unknown) in the output, and `sign_in.mfa_required` is left out of the access file.

Only a GitHub App can list the organization's fine-grained personal access tokens. With a token, the access file's credential values are left out with a `permission_denied` gap.

## Configuration Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `organization` | string | Yes | - | GitHub organization name |
| `app_id` | int | No* | - | GitHub App ID |
| `installation_id` | int | No* | - | GitHub App installation ID |
| `include_patterns` | []string | No | `["*"]` | Glob patterns for repositories to include |
| `exclude_patterns` | []string | No | `[]` | Glob patterns for repositories to exclude |

*Required if using GitHub App authentication

## Secrets

| Name | Required | Description |
|------|----------|-------------|
| `GITHUB_APP_PRIVATE_KEY` | For App auth | GitHub App private key (PEM format) |
| `GITHUB_TOKEN` | For token auth | GitHub API token (short-lived installation token or classic PAT) |

## Pattern Syntax

The include and exclude patterns use glob syntax:

- `*` matches any characters
- `?` matches a single character
- Exclude patterns take precedence over include patterns

### Examples

Archived repositories are skipped automatically and are not assessed for security settings or code scanning status.

```yaml
# Include all non-archived repos, but exclude deprecated repos by name
include_patterns: ["*"]
exclude_patterns: ["*-deprecated"]

# Only include production repos
include_patterns: ["prod-*", "platform-*"]
exclude_patterns: []

# Exclude test and experimental repos
include_patterns: ["*"]
exclude_patterns: ["test-*", "experiment-*", "sandbox-*"]
```

## Selected repositories

A GitHub App can be installed on all of an organization's repositories or only on selected ones. When it is installed on selected repositories, the collector assesses only those, and the patterns narrow them further. The organization's other repositories still count toward `repository_count`, so `repositories_coverage` shows how much of the organization the selection covers, the same way excluded repositories lower it. `scope.repository_selection` records which kind of installation the run used. With an installation token passed as `GITHUB_TOKEN`, the collector reads the selection from `GET /installation/repositories`.

GitHub shows the count of the organization's repositories only to organization owners, so an App installed on selected repositories needs the organization Administration permission (read) for it. Without that permission, `repository_count` and `repositories_coverage` are left out with a gap that names it.

A fine-grained token limited to some repositories has the same limit, but GitHub does not say which repositories a token can read. The collector treats every repository it can list as in scope, so public repositories outside the token's selection are refused and left out as gaps. Use the GitHub App, or a token with access to all repositories, and narrow the scope with the patterns.

## Required GitHub App Permissions

For `trust`-level collection (the default), the app needs:

**Repository permissions:**
- Administration: Read-only (for security settings and `security_and_analysis` field)
- Contents: Read-only (for repository metadata)
- Metadata: Read-only (always required; also covers the rulesets that apply to each default branch)
- Code scanning alerts: Read-only (for code scanning status)
- Secret scanning alerts: Read-only (for secret scanning status)
- Dependabot alerts: Read-only (for dependabot status)

**Organization permissions:**
- Administration: Read-only (for 2FA settings, and for the organization's repository count when the app is installed on selected repositories)
- Members: Read-only (for organization membership)
- Personal access tokens: Read-only (for the fine-grained tokens in the access file)

### Permissions for the access and vulnerability files

A trust run reads these lists only for `artifacts/github.access-posture.json` and `artifacts/github.vuln-scanning.json`. At `audit` and `internal`, the detailed artifact uses the same lists. A missing permission leaves out only the values that come from its list, each with a gap that names the permission.

| File | List | GitHub App permission |
|------|------|-----------------------|
| Access | Members, owners, outside collaborators, and the members and outside collaborators without 2FA | `members: read` |
| Access | SAML identities of the members | `members: read` |
| Access | Installed GitHub Apps | `organization_administration: read` |
| Access | The members' base permission, from the organization | `organization_administration: read` |
| Access | Fine-grained personal access tokens | `organization_personal_access_tokens: read` |
| Access | Deploy keys of each in-scope repository | `administration: read` |
| Vulnerability | Code scanning alerts of each in-scope repository | `security_events: read` |
| Vulnerability | Dependabot alerts of each in-scope repository | `vulnerability_alerts: read` |

With a classic token, the member and SAML lists need `read:org`, and the alert lists need `security_events`. The SAML read needs no extra plan. An organization without GitHub Enterprise Cloud has no SAML identity provider, so `sign_in.sso_configured` is false. To skip a file and its lists, leave its kind out of the `collect` config key:

```yaml
config:
  organization: myorg
  collect: [vcs-posture, vuln-scanning]
```

### Additional permissions for audit and internal levels

The `audit` and `internal` [collection levels](levels.md) add the surfaces
below. A missing permission skips just that surface, so you can grant
incrementally. The collector result records a gap with the permission to
grant.

| Surface | Gating permission | Needed for |
|---------|-------------------|------------|
| Org access control, installed Apps, audit log | `organization_administration: read` | audit / internal |
| Member inventory, SAML NameIDs, per-user 2FA | `members: read` | audit / internal |
| Branch-protection detail, deploy keys | `administration: read` | audit / internal |
| Repository inventory | `metadata: read` | audit / internal |
| Rulesets on each default branch (rules, enforcement, bypass list) | `metadata: read` | audit / internal |
| CODEOWNERS | `contents: read` | audit / internal |
| Security-finding counts and inventories | `secret_scanning_alerts: read`, `security_events: read` (code scanning alerts), `vulnerability_alerts: read` (Dependabot alerts) | audit / internal |
| Repository webhooks | `repository_hooks: read` | audit / internal |
| Organization webhooks | `organization_hooks: read` | audit / internal |
| Self-hosted runners (repo) | `administration: read` | audit / internal |
| Deployment environments + protection rules (repo) | `actions: read` | audit / internal |
| Self-hosted runners (org) | `organization_self_hosted_runners: read` | audit / internal |
| Actions secret names (org, never values) | `organization_secrets: read` | audit / internal |
| Fine-grained PAT grants | `organization_personal_access_tokens: read` | audit / internal, and trust for the access file |

GitHub returns a ruleset's bypass list only to tokens with write access to the
ruleset. With read-only permissions, `bypass_allowed` is `null` on each ruleset
row. Its gap gives you a choice between giving the collector write access to
rulesets and keeping it read-only. Where a repository's admin enforcement
depends on such a ruleset, `admin_enforcement` is `null` as well.

Some surfaces are left out when the underlying feature simply isn't available.
Their gaps list no permission. The **audit log** requires GitHub Enterprise
Cloud, and its gap gives you the choice of moving to it. The **fine-grained
token** inventory requires a fine-grained personal-access-token policy. The
**security-finding counts and inventories** stay empty on repositories that
don't have code scanning, secret scanning, or Dependabot alerts enabled. A run
warning reports this and needs no action. A genuinely missing permission is
reported as a gap with the permission instead, so you can tell the two apart.

For the legacy classic-PAT auth path, the equivalent scopes are `read:org`,
`repo`, `admin:org_hook`, `admin:repo_hook`, and `read:audit_log` (Enterprise
only). The PAT path is fading; migrate to a GitHub App where possible.

### Note on Security Features

Secret scanning and push protection metrics require that these features are enabled for your organization. Some features may require GitHub Advanced Security for private repositories.

## Troubleshooting

**"organization is required"**

The `organization` field must be set in your config:

```yaml
config:
  organization: myorg  # Required
```

**"authentication required"**

You must provide either:
- `GITHUB_TOKEN` secret (for brokered token or PAT auth), or
- `app_id` in config + `GITHUB_APP_PRIVATE_KEY` secret (for App auth)

**"organization not found"**

GitHub has no organization by the configured `organization` name. Check the name for typos. The run fails with exit code 2 and the code `config_invalid`.

**"401 Unauthorized"**

Your credentials are invalid or expired. The run fails with exit code 3 and the code `auth_failed`. For GitHub Apps, ensure the private key matches the app and the app is installed on the organization.

**"403 Forbidden"**

This can occur for two reasons:

1. **Missing permissions**: The authenticated user or app doesn't have the required permissions. See [Required GitHub App Permissions](#required-github-app-permissions) above. A 403 on the organization itself fails the run with exit code 3 and the code `permission_denied`; a 403 on anything else leaves the values it covers out, each with a `permission_denied` gap in `artifacts/github.collector-result.json`. When the GitHub App lacks the permission, the gap names it in `missing_permission`, spelled as the result's `signed_in_as.scopes` list the App's permissions. Each operation in the result has a `permission` field with the permission its call needs.

2. **GitHub Advanced Security not enabled**: For code scanning checks, GitHub returns 403 if Advanced Security is not enabled on the repository. The error message will show: "Advanced Security must be enabled for this repository to use code scanning."
