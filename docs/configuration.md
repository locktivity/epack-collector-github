# Configuration

## Authentication

The collector supports two authentication methods. **GitHub App is recommended** for better security and audit capabilities.

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
     - Contents: Read-only
     - Metadata: Read-only
   - **Organization permissions**:
     - Administration: Read-only
     - Members: Read-only
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

### Classic Personal Access Token (Legacy)

Classic PATs still work but are not recommended for security-focused tools.

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
- `admin:org` - (Optional) Read organization settings for 2FA status

**Note:** Without `admin:org`, the collector will still work but `two_factor_required` will be `null` (unknown) in the output.

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
| `GITHUB_TOKEN` | For PAT auth | Classic personal access token |

## Pattern Syntax

The include and exclude patterns use glob syntax:

- `*` matches any characters
- `?` matches a single character
- Exclude patterns take precedence over include patterns

### Examples

```yaml
# Include all repos except archived ones
include_patterns: ["*"]
exclude_patterns: ["*-archived", "*-deprecated"]

# Only include production repos
include_patterns: ["prod-*", "platform-*"]
exclude_patterns: []

# Exclude test and experimental repos
include_patterns: ["*"]
exclude_patterns: ["test-*", "experiment-*", "sandbox-*"]
```

## Required GitHub App Permissions

For GitHub App authentication, the app needs:

**Repository permissions:**
- Administration: Read-only (for security settings)
- Contents: Read-only (for repository metadata)
- Metadata: Read-only (always required)

**Organization permissions:**
- Administration: Read-only (for 2FA settings)
- Members: Read-only (for organization membership)

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
- `GITHUB_TOKEN` secret (for PAT auth), or
- `app_id` in config + `GITHUB_APP_PRIVATE_KEY` secret (for App auth)

**"401 Unauthorized"**

Your credentials are invalid or expired. For GitHub Apps, ensure the private key matches the app and the app is installed on the organization.

**"403 Forbidden"**

The authenticated user or app doesn't have the required permissions. See [Required GitHub App Permissions](#required-github-app-permissions) above.
