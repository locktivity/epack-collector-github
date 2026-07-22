# Collection Levels

The GitHub collector accepts an optional `level` config knob controlling how
much detail it gathers. There are three levels, and they are cumulative:
`internal` is a strict superset of `audit`, which is a strict superset of
`trust`. No level removes a field that a lower level produced.

## The three levels

| Level | Question it answers | What's in the artifact |
|---|---|---|
| `trust` (default) | Do they pass? | Organization-level pass/fail and percentage signals only. No repository names, member names, configurations, or findings. |
| `audit` | Where is the gap? | Per-repo configuration and rule detail, member and repository inventories, open security-finding counts, organization access-control settings, CODEOWNERS presence, and webhook / deploy-key / runner / installed-App / token counts. |
| `internal` | Who or what specifically? | Per-user two-factor status and last activity, full security-finding inventories, CODEOWNERS content hashes, per-webhook / per-key / per-runner / per-token detail, and a seven-day audit-log slice. |

## Configuration

Set the level in your epack.yaml under the collector's `config` block:

```yaml
collectors:
  github:
    source: locktivity/epack-collector-github@^0.2
    config:
      organization: myorg
      level: audit
```

Default is `trust` when the key is absent or empty. The active level appears in
the output artifact as the top-level `collected_at_level` field.

`audit` and `internal` require additional GitHub App permissions beyond `trust`.
See [Required GitHub App permissions](../README.md#required-github-app-permissions).
When a permission is missing or an organization feature is not available, the
affected surface is skipped and a diagnostic is recorded under
`diagnostics.permission_errors` or `diagnostics.warnings` rather than failing the
run.

## What each level adds, per surface

### Posture (`posture`, `scope`)

- **trust**: branch-protection coverage %, security-features coverage %,
  repositories-coverage % against the include / exclude patterns.

### Access control (`access_control`)

- **trust**: organization-wide two-factor-required flag.
- **audit**: default repository permission, members-can-create-repositories flag
  (from `GET /orgs/{org}`).

### Branch protection rules (`branch_protection_rules`)

- **trust**: per-rule coverage % across in-scope repos (PR required, approving
  reviews, dismiss-stale-reviews, code-owner reviews, status checks, signed
  commits, admin enforcement).

### Security features (`security_features`)

- **trust**: per-feature coverage % (vulnerability alerts, code scanning, secret
  scanning, push protection, Dependabot security updates).
- **audit**: `per_repo[]` rows with the booleans behind the percentages plus
  open-alert counts by type (secret-scanning, code-scanning, Dependabot).
- **internal**: `findings[]` inventories per type (identifiers, severities,
  locations, states; never the secret values themselves).

The open-alert counts (audit) and findings inventories (internal) require both
the matching alert-read permissions and the feature enabled on the repository.
Where code scanning, secret scanning, or Dependabot alerts are not enabled, the
alert fields stay empty and a `warning` is recorded; where the permission is
missing, they stay empty and a `permission_error` is recorded.

The surfaces below are **not collected at trust**; they first appear at
`audit`. Their GitHub App permissions are likewise only exercised at `audit` and
above, so a trust run stays minimal.

### Members (`members`)

- **trust**: omitted.
- **audit**: member / admin / outside-collaborator counts, pending-invitations
  flag, and `per_member[]` rows (login, name, role). `name` is the public
  GitHub profile display name: user-set, so it is empty for anyone who has not
  set one. Member names arrive in one bulk query; outside-collaborator names
  are looked up per login, capped at 200 lookups per run. When name coverage
  is partial for any reason other than an unset profile, a diagnostic warning
  says so.
- **internal**: each member row gains two-factor status and last activity.

### Repositories (`repositories`)

- **trust**: omitted.
- **audit**: counts by visibility and archived / default-branch-protected, and
  `per_repo[]` rows (name, visibility, archived, default branch, timestamps,
  primary language, size) with per-repo branch-protection detail.
- **internal**: each repo row gains low-sensitivity metadata (description,
  topics, license SPDX, stargazer count).

### CODEOWNERS (`codeowners`)

- **trust**: omitted.
- **audit**: `per_repo[]` presence rows (repository, present, path).
- **internal**: each row gains a SHA-256 content hash (computed in-process; file
  contents are never emitted).

### Webhooks (`webhooks`)

- **trust**: omitted.
- **audit**: org / repo webhook counts and count-by-event.
- **internal**: per-webhook rows (id, active, content type, events, URL host only,
  last response code / status).

### Deploy keys (`deploy_keys`)

- **trust**: omitted.
- **audit**: total and read-write counts.
- **internal**: per-key rows (repository, id, title, read-only, timestamps,
  fingerprint; the public key is fingerprinted, never emitted).

### Actions (`actions`)

- **trust**: omitted.
- **audit**: org / repo self-hosted runner counts and org Actions secret count.
- **internal**: per-runner rows (id, name, OS, status, busy, labels) and org
  Actions secret names (names only, never values).

### Apps (`apps`)

- **trust**: omitted.
- **audit**: installed-App count.
- **internal**: per-installation rows (app slug / id, suspended, permissions,
  timestamps, repository selection, subscribed events).

### Fine-grained tokens (`tokens`)

- **trust**: omitted.
- **audit**: grant count.
- **internal**: per-token rows (id, owner, token name, permissions, last-used,
  expires-at; token values are never emitted).

Requires a fine-grained personal-access-token policy on the organization; on an
unavailable feature the surface is omitted and a diagnostic is recorded.

### Audit log (`audit_log`)

- **trust**: omitted.
- **audit**: `count_by_category` of security-relevant events over the last 7 days.
- **internal**: `events[]` slice (action, actor, repo, timestamp). Capped; see
  Truncation.

Requires GitHub Enterprise Cloud; on an unavailable feature the surface is
omitted and a diagnostic is recorded.

## Truncation

Internal-level inventories are capped for very large orgs to keep artifacts
within the per-collector size limit:

| Surface | Cap | Sort (most-significant kept) |
|---|---|---|
| Repositories | 5,000 | private first, then most-recently-pushed |
| Members | 10,000 | role rank (owner first), then login ascending |
| Security findings | 5,000 per type, per repo | severity descending, then created-at |
| Audit log | 5,000 events | API order, most recent first |

When a cap fires, the surface sets a `truncated` flag and a dropped-row count.

## Never emitted, at any level

Repository contents, pull request and issue bodies, full webhook URLs and
webhook secrets, deploy-key and SSH public-key material (fingerprinted only),
Actions secret values, CODEOWNERS file contents (hashed only), and token values
are never collected.
