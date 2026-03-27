# GitHub Posture Collector

The GitHub Posture Collector gathers security posture metrics from your GitHub organization.

## What It Collects

This collector queries your GitHub organization and aggregates security posture coverage metrics:

- **Scope**: The include/exclude patterns and repositories coverage percentage
- **Posture Summary**: High-level coverage percentages for branch protection and security features
- **Access Control**: Organization-level 2FA enforcement status
- **Branch Protection Rules**: Per-rule coverage percentages (PR requirements, reviews, status checks, signed commits, admin enforcement)
- **Security Features**: Per-feature coverage percentages (vulnerability alerts, code scanning, secret scanning, push protection, Dependabot)

All metrics are expressed as coverage percentages (0-100) rather than raw counts, making it easy to track and compare security posture over time. The scope is included in the output so receivers can understand exactly what was covered.

## Use Cases

- **Third-party risk assessments**: Provide evidence of your GitHub security posture to customers and auditors
- **Continuous assurance**: Automate evidence collection for ongoing compliance monitoring
- **Security benchmarking**: Track security posture improvements over time

## How It Works

1. The collector authenticates to GitHub using either:
   - a GitHub App private key flow, or
   - a `GITHUB_TOKEN` supplied by the runtime
2. It queries the GitHub GraphQL API to fetch repository metadata and branch protection rules
3. It queries the GitHub REST API to fetch security settings (secret scanning, push protection, Dependabot)
4. Metrics are aggregated into coverage percentages
5. The output is wrapped in the epack collector protocol envelope and written to stdout

## Authentication

**GitHub App authentication is recommended** for manual setups:
- Not tied to a user account
- Better audit logging
- Higher rate limits
- Recommended by GitHub for org-level integrations

When the collector runs under a managed or brokered runtime, `GITHUB_TOKEN` may be a short-lived installation token instead of a user PAT.

See [Configuration](configuration.md) for setup instructions.
