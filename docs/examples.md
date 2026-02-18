# Examples

## Basic Usage

### Using GitHub App (Recommended)

```yaml
stream: myorg/github-posture

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

Then run:

```bash
export GITHUB_APP_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
epack collect
```

See [Configuration](configuration.md) for GitHub App setup instructions.

### Using Classic PAT (Legacy)

```yaml
stream: myorg/github-posture

collectors:
  github:
    source: locktivity/epack-collector-github@^0.1
    config:
      organization: myorg
    secrets:
      - GITHUB_TOKEN
```

Then run:

```bash
export GITHUB_TOKEN=ghp_xxxx
epack collect
```

## Filtering Repositories

### Exclude Archived Repositories

```yaml
collectors:
  github:
    source: locktivity/epack-collector-github@^0.1
    config:
      organization: myorg
      app_id: 123456
      installation_id: 78901234
      exclude_patterns:
        - "*-archived"
        - "*-deprecated"
        - "*-old"
    secrets:
      - GITHUB_APP_PRIVATE_KEY
```

### Only Production Repositories

```yaml
collectors:
  github:
    source: locktivity/epack-collector-github@^0.1
    config:
      organization: myorg
      app_id: 123456
      installation_id: 78901234
      include_patterns:
        - "prod-*"
        - "platform-*"
        - "service-*"
    secrets:
      - GITHUB_APP_PRIVATE_KEY
```

## Sample Output

```json
{
  "protocol_version": 1,
  "data": {
    "schema_version": "1.0.0",
    "collected_at": "2026-02-23T14:30:00Z",
    "organization": "myorg",
    "scope": {
      "include_patterns": ["*"],
      "exclude_patterns": ["*-archived", "test-*"],
      "repositories_coverage": 79
    },
    "posture": {
      "branch_protection_coverage": 93,
      "security_features_coverage": 72
    },
    "access_control": {
      "two_factor_required": true
    },
    "branch_protection_rules": {
      "pull_request_required": 93,
      "approving_reviews": 89,
      "dismiss_stale_reviews": 84,
      "code_owner_reviews": 33,
      "status_checks": 87,
      "signed_commits": 49,
      "admin_enforcement": 78
    },
    "security_features": {
      "vulnerability_alerts": 95,
      "code_scanning": 78,
      "secret_scanning": 82,
      "secret_scanning_push_protection": 60,
      "dependabot_security_updates": 51
    }
  }
}
```

All coverage values are percentages (0-100). The `security_features_coverage` is the average of all five security features.

The `scope` field records the filters applied during collection. The `repositories_coverage` percentage indicates what proportion of the organization's repositories were assessed (e.g., 79% means 79% of repos matched the include/exclude filters).

The `access_control` section provides organization-level security posture:
- `two_factor_required`: Whether 2FA is enforced for all org members

**Note:** `two_factor_required` may be `null` if the token lacks sufficient permissions (requires `admin:org` scope for PATs, or Organization Administration permission for GitHub Apps).

**SSO Limitation:** SSO status is not included in the output because GitHub does not provide a reliable API to detect SAML SSO configuration. The GraphQL `samlIdentityProvider` field has a known permission bug with GitHub Apps ([discussion](https://github.com/orgs/community/discussions/45063)), and no REST API endpoint returns SSO status.

## CI/CD Integration

### GitHub Actions (with GitHub App)

```yaml
name: Collect Evidence

on:
  schedule:
    - cron: "0 0 * * 1"  # Weekly on Monday
  workflow_dispatch:

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install epack
        run: |
          curl -sSL https://github.com/locktivity/epack/releases/latest/download/epack-linux-amd64 -o epack
          chmod +x epack
          sudo mv epack /usr/local/bin/

      - name: Collect evidence
        run: epack collect --frozen
        env:
          GITHUB_APP_PRIVATE_KEY: ${{ secrets.GITHUB_APP_PRIVATE_KEY }}

      - name: Upload pack
        uses: actions/upload-artifact@v4
        with:
          name: evidence-pack
          path: "*.pack"
```

Store the GitHub App private key as a repository secret named `GITHUB_APP_PRIVATE_KEY`.
