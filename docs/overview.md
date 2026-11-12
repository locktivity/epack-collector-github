# GitHub Posture Collector

The GitHub Posture Collector gathers security posture metrics from your GitHub organization.

## What It Collects

This collector queries your GitHub organization and aggregates security posture coverage metrics:

- **Scope**: The include/exclude patterns and repositories coverage percentage
- **Posture Summary**: High-level coverage percentages for branch protection and security features
- **Access Control**: Organization-level 2FA enforcement status
- **Branch Protection Rules**: Per-rule coverage percentages from classic branch protection rules and rulesets (PR requirements, reviews, status checks, signed commits, admin enforcement, force pushes, deletions, linear history)
- **Security Features**: Per-feature coverage percentages (vulnerability alerts, code scanning, secret scanning, push protection, Dependabot)

All metrics are expressed as coverage percentages (0-100) rather than raw counts, making it easy to track and compare security posture over time. The scope is included in the output, with the repository counts the percentages are taken over, so receivers can understand exactly what was covered.

The collector also writes three files in epack's normalized formats:

- **`artifacts/github.vcs-posture.json`** (`evidencepack/vcs-posture@v1`): branch protection coverage and the share of repositories the scan covered
- **`artifacts/github.access-posture.json`** (`evidencepack/access-posture@v1`): the two-factor requirement, SAML single sign-on, members, outside collaborators, owners and their two-factor authentication, fine-grained personal access tokens, deploy keys, and installed GitHub Apps
- **`artifacts/github.vuln-scanning.json`** (`evidencepack/vuln-scanning@v1`): Dependabot, code scanning, and secret scanning coverage, with the open Dependabot and code scanning alerts by severity and the overdue ones

A value GitHub has no data for, such as when a member last signed in, is left out with an `unsupported` gap. A value GitHub reports that the collector does not read, such as whether the organization requires SAML single sign-on, is left out with a `not_read` gap. You can leave any of these files out with the `collect` config key. The calls that feed only that file are then skipped.

## Not Collected

GitHub offers the following through its API, and the collector does not read them.

- **Credentials authorized for SAML single sign-on.** For an organization that uses SAML single sign-on, GitHub lists the personal access tokens, SSH keys and OAuth app tokens that members have authorized for it. The credentials the collector counts are fine-grained personal access tokens and deploy keys.
- **IP allow list.** GitHub's GraphQL API returns whether the organization has an IP allow list enabled, and the allowed IP addresses.
- **GitHub Actions workflow permissions.** GitHub reports the default permissions of the `GITHUB_TOKEN` in the organization's workflows, and whether GitHub Actions can approve pull requests.

## Use Cases

- **Third-party risk assessments**: Provide evidence of your GitHub security posture to customers and auditors
- **Continuous assurance**: Automate evidence collection for ongoing compliance monitoring
- **Security benchmarking**: Track security posture improvements over time

## How It Works

1. The collector authenticates to GitHub using either:
   - a GitHub App private key flow, or
   - a `GITHUB_TOKEN` supplied by the runtime
2. It queries the GitHub GraphQL API to fetch repository metadata and classic branch protection rules
3. It queries the GitHub REST API to fetch the rulesets that apply to each default branch and security settings (secret scanning, push protection, Dependabot)
4. For the access file, it reads the organization's members, owners, outside collaborators, and the members and outside collaborators without two-factor authentication. It also reads the fine-grained token grants, deploy keys, and installed Apps, and the SAML identities from the GraphQL API
5. For the vulnerability file, it lists each in-scope repository's open code scanning and Dependabot alerts
6. Metrics are aggregated into coverage percentages
7. The output is wrapped in the epack collector protocol envelope and written to stdout, with a collector result artifact that records each value the collector could not read and why

## Authentication

**GitHub App authentication is recommended** for manual setups:
- Not tied to a user account
- Better audit logging
- Higher rate limits
- Recommended by GitHub for org-level integrations

When the collector runs under a managed or brokered runtime, `GITHUB_TOKEN` may be a short-lived installation token instead of a user PAT.

See [Configuration](configuration.md) for setup instructions.
