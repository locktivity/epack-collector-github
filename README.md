# epack-collector-github

An epack collector built with the [Component SDK](https://github.com/locktivity/epack) that gathers GitHub organization security posture metrics.

See [docs/](docs/) for detailed documentation.

## What It Collects

- **Posture Summary**: Branch protection and security features coverage percentages
- **Access Control**: Organization-level 2FA enforcement status
- **Branch Protection Rules**: Per-rule coverage (PR requirements, reviews, status checks, signed commits, admin enforcement)
- **Security Features**: Per-feature coverage (vulnerability alerts, code scanning, secret scanning, push protection, Dependabot)

## Quick Start

### Using GitHub App (Recommended)

GitHub App authentication provides better security: not tied to a user, better audit logging, higher rate limits.

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

```bash
export GITHUB_APP_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
epack collect
```

See [docs/configuration.md](docs/configuration.md) for GitHub App setup instructions.

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

```bash
export GITHUB_TOKEN=ghp_xxxx
epack collect
```

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
export GITHUB_TOKEN=ghp_xxxx          # Personal access token with repo scope (add admin:org for 2FA)
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
