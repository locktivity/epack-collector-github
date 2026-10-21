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

### Using `GITHUB_TOKEN` (Brokered Token or PAT)

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

`GITHUB_TOKEN` can be a short-lived installation token injected by the runtime, or a classic PAT for manual use.

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
      "repositories_coverage": 79,
      "repository_count": 142,
      "included_repository_count": 113
    },
    "posture": {
      "branch_protection_coverage": 93,
      "protected_repository_count": 106,
      "security_features_coverage": 73
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
      "admin_enforcement": 78,
      "force_pushes_blocked": 93,
      "deletions_blocked": 93,
      "linear_history": 21,
      "repository_counts": {
        "pull_request_required": 106,
        "approving_reviews": 101,
        "dismiss_stale_reviews": 95,
        "code_owner_reviews": 38,
        "status_checks": 99,
        "signed_commits": 56,
        "admin_enforcement": 89,
        "force_pushes_blocked": 106,
        "deletions_blocked": 106,
        "linear_history": 24
      }
    },
    "security_features": {
      "vulnerability_alerts": 95,
      "code_scanning": 78,
      "secret_scanning": 82,
      "secret_scanning_push_protection": 60,
      "dependabot_security_updates": 51,
      "repository_counts": {
        "vulnerability_alerts": 108,
        "code_scanning": 89,
        "secret_scanning": 93,
        "secret_scanning_push_protection": 68,
        "dependabot_security_updates": 58
      }
    }
  }
}
```

All coverage values are percentages (0-100), rounded down. The `security_features_coverage` is the average of all five security features. Beside each other percentage is the count of repositories it is taken of: `protected_repository_count`, and a `repository_counts` object in `branch_protection_rules` and in `security_features`. A count is `null` when its percentage is, except that with no repository in scope the counts are 0. A value is `null` when it could not be determined for every repository, and `artifacts/github.collector-result.json` records a gap with the reason, as does `diagnostics`. The percentages are also `null` when no repository is in scope.

The `scope` field records the filters applied during collection. The `repositories_coverage` percentage indicates what proportion of the organization's repositories were assessed (e.g., 79% means 79% of repos matched the include/exclude filters). `repository_count` counts every repository in the organization, archived ones included, and `included_repository_count` counts the ones in scope, which the other percentages are taken over.

The `access_control` section provides organization-level security posture:
- `two_factor_required`: Whether 2FA is enforced for all org members

**Note:** `two_factor_required` is `null`, with a `permission_denied` gap in the collector result, if the token lacks sufficient permissions (requires `admin:org` scope for PATs, or Organization Administration permission for GitHub Apps). The normalized `vcs-posture` artifact then leaves the setting out rather than reporting it as not required.

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
