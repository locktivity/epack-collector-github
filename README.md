# epack-collector-github

An epack collector built with the [Component SDK](https://github.com/locktivity/epack) that gathers GitHub organization security posture metrics.

See [docs/](docs/) for detailed documentation.

## What It Collects

- **Posture Summary**: Branch protection and security features coverage percentages
- **Access Control**: Organization-level 2FA enforcement status
- **Branch Protection Rules**: Per-rule coverage (PR requirements, reviews, status checks, signed commits, admin enforcement)
- **Security Features**: Per-feature coverage (vulnerability alerts, code scanning, secret scanning, push protection, Dependabot)

At `audit` and `internal` levels the collector also gathers per-repo
configuration, member and repository inventories, security-finding inventories,
CODEOWNERS, webhooks, deploy keys, Actions runners, installed GitHub Apps,
fine-grained token grants, and a security-relevant audit-log slice. See
[Collection levels](#collection-levels).

## Collection levels

The collector reads the `level` config key (`trust`, `audit`, or `internal`,
default `trust`) and gathers more detail at higher levels. Levels are
cumulative. The level it ran at is stamped on the output as
`collected_at_level`.

- **trust**: organization-level pass/fail and percentage signals only. No repo
  names, member names, configurations, or findings.
- **audit**: adds per-repo configuration and rule details, member and repository
  inventories, open security-finding counts, CODEOWNERS presence, and webhook /
  deploy-key / runner / installed-App / token counts.
- **internal**: adds per-user 2FA and last activity, full security-finding
  inventories, CODEOWNERS content hashes, per-webhook / per-key / per-runner /
  per-token detail, and a seven-day audit-log slice.

The collector never emits repository contents, pull request or issue bodies,
webhook secrets, or token values at any level.

See [docs/levels.md](docs/levels.md) for the full per-surface breakdown.

```yaml
collectors:
  github:
    source: locktivity/epack-collector-github@^0.2
    config:
      organization: myorg
      level: audit
```

> **Upgrading to v0.2.x:** the `audit` and `internal` levels require additional
> GitHub App permissions (see below). Bumping the collector version without
> granting them results in diagnostic warnings on the affected surfaces, not a
> failed run. The surfaces that need new permissions are simply skipped until
> the App is re-authorized.

## Required GitHub App permissions

`trust`-level collection needs only the permissions the collector has always
required. `audit` and `internal` add the surfaces below. A missing permission
skips just that surface (with a diagnostic), so you can grant incrementally.

| Surface | Gating permission | Needed for |
|---------|-------------------|------------|
| Org access control, installed Apps, audit log | `organization_administration: read` | audit / internal |
| Member inventory, per-user 2FA | `members: read` | audit / internal |
| Branch-protection detail, deploy keys | `administration: read` | audit / internal |
| Repository inventory | `metadata: read` | audit / internal |
| CODEOWNERS | `contents: read` | audit / internal |
| Security-finding counts and inventories | `secret_scanning_alerts: read`, `code_scanning_alerts: read`, `dependabot_alerts: read` | audit / internal |
| Repository webhooks | `repository_hooks: read` | audit / internal |
| Organization webhooks | `organization_hooks: read` | audit / internal |
| Actions runners + workflow summaries (repo) | `actions: read` | audit / internal |
| Self-hosted runners (org) | `organization_self_hosted_runners: read` | audit / internal |
| Actions secret names (org, never values) | `organization_secrets: read` | audit / internal |
| Fine-grained PAT grants | `organization_personal_access_tokens: read` | audit / internal |

Some surfaces degrade to a diagnostic warning (rather than a permission error)
when the underlying feature simply isn't available: the **audit log** requires
GitHub Enterprise Cloud, the **fine-grained token** inventory requires a
fine-grained personal-access-token policy, and the **security-finding counts and
inventories** stay empty on repositories that don't have code scanning, secret
scanning, or Dependabot alerts enabled. A genuinely missing permission is
reported as a permission error instead, so you can tell the two apart.

For the legacy classic-PAT auth path, the equivalent scopes are `read:org`,
`repo`, `admin:org_hook`, `admin:repo_hook`, and `read:audit_log` (Enterprise
only). The PAT path is fading; migrate to a GitHub App where possible.

## Quick Start

### Using GitHub App (Recommended)

GitHub App authentication provides better security: not tied to a user, better audit logging, higher rate limits.

```yaml
stream: myorg/github-posture

collectors:
  github:
    source: locktivity/epack-collector-github@^0.2
    config:
      organization: myorg
      app_id: 123456
      installation_id: 78901234
    secrets:
      - GITHUB_APP_PRIVATE_KEY
```

```bash
export GITHUB_APP_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
epack collect
```

See [docs/configuration.md](docs/configuration.md) for GitHub App setup instructions.

### Using `GITHUB_TOKEN` (Brokered Token or PAT)

```yaml
stream: myorg/github-posture

collectors:
  github:
    source: locktivity/epack-collector-github@^0.2
    config:
      organization: myorg
    secrets:
      - GITHUB_TOKEN
```

```bash
export GITHUB_TOKEN=ghp_xxxx
epack collect
```

`GITHUB_TOKEN` can be either:
- a short-lived GitHub installation token injected by a trusted runtime or broker
- a classic personal access token for manual setups

## Binary Download

Download from [GitHub Releases](https://github.com/locktivity/epack-collector-github/releases).

All binaries include [SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) provenance. Verify with:

```bash
slsa-verifier verify-artifact epack-collector-github-darwin-arm64 \
  --provenance-path epack-collector-github-darwin-arm64.intoto.jsonl \
  --source-uri github.com/locktivity/epack-collector-github
```

## Development

```bash
# Build
make build

# Run locally (with epack SDK)
epack sdk run ./epack-collector-github

# Watch mode: auto-rebuild on file changes
epack sdk run --watch .

# Run conformance tests
epack sdk test ./epack-collector-github

# Or use make targets
make sdk-test
make sdk-run
```

## Testing

The project has three levels of tests:

### Unit Tests

Unit tests use mock interfaces to test collector logic without network calls.

```bash
go test ./...

# Or with make
make test
```

### HTTP-Level Tests

Tests in `internal/github/client_test.go` use `httptest.Server` to verify actual GraphQL request/response behavior. These run automatically with unit tests and verify:

- GraphQL query structure and field selection
- Response parsing and error handling
- Pagination cursor handling
- Rate limit error responses
- Context cancellation

### End-to-End Tests

E2E tests make real HTTP requests to the GitHub API. They are excluded from normal test runs via a build tag and require environment variables:

```bash
# Set required environment variables
export GITHUB_TOKEN=ghp_xxxx          # GitHub API token (classic PAT or short-lived installation token)
export GITHUB_ORG=your-org-name       # Organization to test against

# Run e2e tests (no build step needed - tests run directly)
go test -v -tags=e2e ./internal/collector/...
```

For GitHub App authentication instead of a PAT:

```bash
export GITHUB_APP_ID=123456
export GITHUB_APP_INSTALLATION_ID=78901234
export GITHUB_APP_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
export GITHUB_ORG=your-org-name

go test -v -tags=e2e ./internal/collector/...
```

### Conformance Tests

The epack SDK includes conformance tests that verify the collector meets the component specification:

```bash
# Build first
make build

# Run conformance tests
epack sdk test ./epack-collector-github

# Or use make
make sdk-test
```

### Linting

```bash
make lint
```

### Build for All Platforms

```bash
make build-all
```

## Release

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The GitHub Action will:
1. Run tests and conformance checks
2. Build multi-platform binaries (linux/darwin, amd64/arm64)
3. Generate SLSA Level 3 provenance attestations
4. Publish to GitHub Releases

## License

Apache License 2.0
