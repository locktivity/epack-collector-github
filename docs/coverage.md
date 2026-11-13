# GitHub API coverage

What the collector reads of the GitHub API, and what it leaves out, checked against the GitHub API description at revision bd6df26d2a01: https://github.com/github/rest-api-description, descriptions/ghec/ghec.json.

| | Operations |
|---|---|
| In the description | 1577 |
| Read operations in scope | 777 |
| Called by the collector | 25 |
| Not collected | 276, in 15 items |
| Left out as irrelevant | 472 |

## What the collector reads

- **actions:** `actions/list-self-hosted-runners-for-org` (GET /orgs/{org}/actions/runners); `actions/list-org-secrets` (GET /orgs/{org}/actions/secrets); `actions/list-self-hosted-runners-for-repo` (GET /repos/{owner}/{repo}/actions/runners)
- **apps:** `apps/create-installation-access-token` (POST /app/installations/{installation_id}/access_tokens); `apps/list-repos-accessible-to-installation` (GET /installation/repositories)
- **code-scanning:** `code-scanning/list-alerts-for-repo` (GET /repos/{owner}/{repo}/code-scanning/alerts); `code-scanning/list-recent-analyses` (GET /repos/{owner}/{repo}/code-scanning/analyses); `code-scanning/get-default-setup` (GET /repos/{owner}/{repo}/code-scanning/default-setup)
- **dependabot:** `dependabot/list-alerts-for-repo` (GET /repos/{owner}/{repo}/dependabot/alerts)
- **deploy-keys:** `repos/list-deploy-keys` (GET /repos/{owner}/{repo}/keys)
- **deployments:** `repos/get-all-environments` (GET /repos/{owner}/{repo}/environments)
- **orgs:** `orgs/get` (GET /orgs/{org}); `orgs/get-audit-log` (GET /orgs/{org}/audit-log); `orgs/list-webhooks` (GET /orgs/{org}/hooks); `orgs/list-app-installations` (GET /orgs/{org}/installations); `orgs/list-pending-invitations` (GET /orgs/{org}/invitations); `orgs/list-members` (GET /orgs/{org}/members); `orgs/list-outside-collaborators` (GET /orgs/{org}/outside_collaborators); `orgs/list-pat-grants` (GET /orgs/{org}/personal-access-tokens)
- **repos:** `repos/get` (GET /repos/{owner}/{repo}); `repos/get-content` (GET /repos/{owner}/{repo}/contents/{path}); `repos/list-webhooks` (GET /repos/{owner}/{repo}/hooks); `repos/get-branch-rules` (GET /repos/{owner}/{repo}/rules/branches/{branch}); `repos/get-repo-ruleset` (GET /repos/{owner}/{repo}/rulesets/{ruleset_id})
- **secret-scanning:** `secret-scanning/list-alerts-for-repo` (GET /repos/{owner}/{repo}/secret-scanning/alerts)

## Not collected

### Actions policies and runner configuration

Which actions and reusable workflows the organization allows, the default permissions of the GITHUB_TOKEN in workflows, whether Actions can approve pull requests, policies for workflows from forks, artifact and log retention, self-hosted runner groups and the repositories they serve, the OpenID Connect subject claim settings, and private network configurations for hosted runners. The collector lists the organization's and each repository's self-hosted runners.

- `oidc/list-oidc-custom-property-inclusions-for-enterprise` (GET /enterprises/{enterprise}/actions/oidc/customization/properties/repo)
- `enterprise-admin/get-github-actions-permissions-enterprise` (GET /enterprises/{enterprise}/actions/permissions)
- `enterprise-admin/get-artifact-and-log-retention-settings` (GET /enterprises/{enterprise}/actions/permissions/artifact-and-log-retention)
- `enterprise-admin/get-fork-pr-contributor-approval-permissions` (GET /enterprises/{enterprise}/actions/permissions/fork-pr-contributor-approval)
- `enterprise-admin/get-private-repo-fork-pr-workflows-settings` (GET /enterprises/{enterprise}/actions/permissions/fork-pr-workflows-private-repos)
- `enterprise-admin/list-selected-organizations-enabled-github-actions-enterprise` (GET /enterprises/{enterprise}/actions/permissions/organizations)
- `enterprise-admin/get-allowed-actions-enterprise` (GET /enterprises/{enterprise}/actions/permissions/selected-actions)
- `enterprise-admin/get-self-hosted-runners-permissions` (GET /enterprises/{enterprise}/actions/permissions/self-hosted-runners)
- `actions/get-github-actions-default-workflow-permissions-enterprise` (GET /enterprises/{enterprise}/actions/permissions/workflow)
- `actions/get-enterprise-actions-policies` (GET /enterprises/{enterprise}/actions/policies)
- `actions/get-enterprise-actions-policy` (GET /enterprises/{enterprise}/actions/policies/{policy_id})
- `enterprise-admin/list-self-hosted-runner-groups-for-enterprise` (GET /enterprises/{enterprise}/actions/runner-groups)
- `enterprise-admin/get-self-hosted-runner-group-for-enterprise` (GET /enterprises/{enterprise}/actions/runner-groups/{runner_group_id})
- `enterprise-admin/list-org-access-to-self-hosted-runner-group-in-enterprise` (GET /enterprises/{enterprise}/actions/runner-groups/{runner_group_id}/organizations)
- `enterprise-admin/list-self-hosted-runners-in-group-for-enterprise` (GET /enterprises/{enterprise}/actions/runner-groups/{runner_group_id}/runners)
- `oidc/list-oidc-custom-property-inclusions-for-org` (GET /orgs/{org}/actions/oidc/customization/properties/repo)
- `oidc/get-oidc-custom-sub-template-for-org` (GET /orgs/{org}/actions/oidc/customization/sub)
- `actions/get-github-actions-permissions-organization` (GET /orgs/{org}/actions/permissions)
- `actions/get-artifact-and-log-retention-settings-organization` (GET /orgs/{org}/actions/permissions/artifact-and-log-retention)
- `actions/get-fork-pr-contributor-approval-permissions-organization` (GET /orgs/{org}/actions/permissions/fork-pr-contributor-approval)
- `actions/get-private-repo-fork-pr-workflows-settings-organization` (GET /orgs/{org}/actions/permissions/fork-pr-workflows-private-repos)
- `actions/list-selected-repositories-enabled-github-actions-organization` (GET /orgs/{org}/actions/permissions/repositories)
- `actions/get-allowed-actions-organization` (GET /orgs/{org}/actions/permissions/selected-actions)
- `actions/get-self-hosted-runners-permissions-organization` (GET /orgs/{org}/actions/permissions/self-hosted-runners)
- `actions/list-selected-repositories-self-hosted-runners-organization` (GET /orgs/{org}/actions/permissions/self-hosted-runners/repositories)
- `actions/get-github-actions-default-workflow-permissions-organization` (GET /orgs/{org}/actions/permissions/workflow)
- `actions/get-org-actions-policies` (GET /orgs/{org}/actions/policies)
- `actions/get-org-actions-policy` (GET /orgs/{org}/actions/policies/{policy_id})
- `actions/list-self-hosted-runner-groups-for-org` (GET /orgs/{org}/actions/runner-groups)
- `actions/get-self-hosted-runner-group-for-org` (GET /orgs/{org}/actions/runner-groups/{runner_group_id})
- `actions/list-github-hosted-runners-in-group-for-org` (GET /orgs/{org}/actions/runner-groups/{runner_group_id}/hosted-runners)
- `actions/list-repo-access-to-self-hosted-runner-group-in-org` (GET /orgs/{org}/actions/runner-groups/{runner_group_id}/repositories)
- `actions/list-self-hosted-runners-in-group-for-org` (GET /orgs/{org}/actions/runner-groups/{runner_group_id}/runners)
- `hosted-compute/list-network-configurations-for-org` (GET /orgs/{org}/settings/network-configurations)
- `hosted-compute/get-network-configuration-for-org` (GET /orgs/{org}/settings/network-configurations/{network_configuration_id})
- `hosted-compute/get-network-settings-for-org` (GET /orgs/{org}/settings/network-settings/{network_settings_id})
- `actions/get-custom-oidc-sub-claim-for-repo` (GET /repos/{owner}/{repo}/actions/oidc/customization/sub)
- `actions/get-github-actions-permissions-repository` (GET /repos/{owner}/{repo}/actions/permissions)
- `actions/get-workflow-access-to-repository` (GET /repos/{owner}/{repo}/actions/permissions/access)
- `actions/get-artifact-and-log-retention-settings-repository` (GET /repos/{owner}/{repo}/actions/permissions/artifact-and-log-retention)
- `actions/get-fork-pr-contributor-approval-permissions-repository` (GET /repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval)
- `actions/get-private-repo-fork-pr-workflows-settings-repository` (GET /repos/{owner}/{repo}/actions/permissions/fork-pr-workflows-private-repos)
- `actions/get-allowed-actions-repository` (GET /repos/{owner}/{repo}/actions/permissions/selected-actions)
- `actions/get-github-actions-default-workflow-permissions-repository` (GET /repos/{owner}/{repo}/actions/permissions/workflow)
- `actions/get-repo-actions-policies` (GET /repos/{owner}/{repo}/actions/policies)
- `actions/get-repo-actions-policy` (GET /repos/{owner}/{repo}/actions/policies/{policy_id})

### Secrets and variables beyond the organization's Actions secrets

Repository and environment Actions secrets and variables, organization Actions variables, Codespaces and Dependabot secrets, Copilot coding agent secrets and variables, and private registry configurations. The collector lists the organization's Actions secrets by name.

- `actions/get-org-public-key` (GET /orgs/{org}/actions/secrets/public-key)
- `actions/get-org-secret` (GET /orgs/{org}/actions/secrets/{secret_name})
- `actions/list-selected-repos-for-org-secret` (GET /orgs/{org}/actions/secrets/{secret_name}/repositories)
- `actions/list-org-variables` (GET /orgs/{org}/actions/variables)
- `actions/get-org-variable` (GET /orgs/{org}/actions/variables/{name})
- `actions/list-selected-repos-for-org-variable` (GET /orgs/{org}/actions/variables/{name}/repositories)
- `agents/list-org-secrets` (GET /orgs/{org}/agents/secrets)
- `agents/get-org-public-key` (GET /orgs/{org}/agents/secrets/public-key)
- `agents/get-org-secret` (GET /orgs/{org}/agents/secrets/{secret_name})
- `agents/list-selected-repos-for-org-secret` (GET /orgs/{org}/agents/secrets/{secret_name}/repositories)
- `agents/list-org-variables` (GET /orgs/{org}/agents/variables)
- `agents/get-org-variable` (GET /orgs/{org}/agents/variables/{name})
- `agents/list-selected-repos-for-org-variable` (GET /orgs/{org}/agents/variables/{name}/repositories)
- `codespaces/list-org-secrets` (GET /orgs/{org}/codespaces/secrets)
- `codespaces/get-org-public-key` (GET /orgs/{org}/codespaces/secrets/public-key)
- `codespaces/get-org-secret` (GET /orgs/{org}/codespaces/secrets/{secret_name})
- `codespaces/list-selected-repos-for-org-secret` (GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories)
- `dependabot/list-org-secrets` (GET /orgs/{org}/dependabot/secrets)
- `dependabot/get-org-public-key` (GET /orgs/{org}/dependabot/secrets/public-key)
- `dependabot/get-org-secret` (GET /orgs/{org}/dependabot/secrets/{secret_name})
- `dependabot/list-selected-repos-for-org-secret` (GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories)
- `private-registries/list-org-private-registries` (GET /orgs/{org}/private-registries)
- `private-registries/get-org-public-key` (GET /orgs/{org}/private-registries/public-key)
- `private-registries/get-org-private-registry` (GET /orgs/{org}/private-registries/{secret_name})
- `actions/list-repo-organization-secrets` (GET /repos/{owner}/{repo}/actions/organization-secrets)
- `actions/list-repo-organization-variables` (GET /repos/{owner}/{repo}/actions/organization-variables)
- `actions/list-repo-secrets` (GET /repos/{owner}/{repo}/actions/secrets)
- `actions/get-repo-public-key` (GET /repos/{owner}/{repo}/actions/secrets/public-key)
- `actions/get-repo-secret` (GET /repos/{owner}/{repo}/actions/secrets/{secret_name})
- `actions/list-repo-variables` (GET /repos/{owner}/{repo}/actions/variables)
- `actions/get-repo-variable` (GET /repos/{owner}/{repo}/actions/variables/{name})
- `agents/list-repo-organization-secrets` (GET /repos/{owner}/{repo}/agents/organization-secrets)
- `agents/list-repo-organization-variables` (GET /repos/{owner}/{repo}/agents/organization-variables)
- `agents/list-repo-secrets` (GET /repos/{owner}/{repo}/agents/secrets)
- `agents/get-repo-public-key` (GET /repos/{owner}/{repo}/agents/secrets/public-key)
- `agents/get-repo-secret` (GET /repos/{owner}/{repo}/agents/secrets/{secret_name})
- `agents/list-repo-variables` (GET /repos/{owner}/{repo}/agents/variables)
- `agents/get-repo-variable` (GET /repos/{owner}/{repo}/agents/variables/{name})
- `codespaces/list-repo-secrets` (GET /repos/{owner}/{repo}/codespaces/secrets)
- `codespaces/get-repo-public-key` (GET /repos/{owner}/{repo}/codespaces/secrets/public-key)
- `codespaces/get-repo-secret` (GET /repos/{owner}/{repo}/codespaces/secrets/{secret_name})
- `dependabot/list-repo-secrets` (GET /repos/{owner}/{repo}/dependabot/secrets)
- `dependabot/get-repo-public-key` (GET /repos/{owner}/{repo}/dependabot/secrets/public-key)
- `dependabot/get-repo-secret` (GET /repos/{owner}/{repo}/dependabot/secrets/{secret_name})
- `actions/list-environment-secrets` (GET /repos/{owner}/{repo}/environments/{environment_name}/secrets)
- `actions/get-environment-public-key` (GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/public-key)
- `actions/get-environment-secret` (GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name})
- `actions/list-environment-variables` (GET /repos/{owner}/{repo}/environments/{environment_name}/variables)
- `actions/get-environment-variable` (GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name})
- `codespaces/list-secrets-for-authenticated-user` (GET /user/codespaces/secrets)
- `codespaces/get-public-key-for-authenticated-user` (GET /user/codespaces/secrets/public-key)
- `codespaces/get-secret-for-authenticated-user` (GET /user/codespaces/secrets/{secret_name})
- `codespaces/list-repositories-for-secret-for-authenticated-user` (GET /user/codespaces/secrets/{secret_name}/repositories)

### Teams

Teams, their members and maintainers, the repositories each team can reach and with what permission, and the identity provider groups connected to teams. The collector counts members, administrators and outside collaborators for the organization as a whole.

- `teams/external-idp-group-info-for-org` (GET /orgs/{org}/external-group/{group_id})
- `teams/list-external-idp-groups-for-org` (GET /orgs/{org}/external-groups)
- `teams/list-idp-groups-for-org` (GET /orgs/{org}/team-sync/groups)
- `teams/list` (GET /orgs/{org}/teams)
- `teams/get-by-name` (GET /orgs/{org}/teams/{team_slug})
- `teams/list-linked-external-idp-groups-to-team-for-org` (GET /orgs/{org}/teams/{team_slug}/external-groups)
- `teams/list-pending-invitations-in-org` (GET /orgs/{org}/teams/{team_slug}/invitations)
- `teams/list-members-in-org` (GET /orgs/{org}/teams/{team_slug}/members)
- `teams/get-membership-for-user-in-org` (GET /orgs/{org}/teams/{team_slug}/memberships/{username})
- `teams/list-repos-in-org` (GET /orgs/{org}/teams/{team_slug}/repos)
- `teams/check-permissions-for-repo-in-org` (GET /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo})
- `teams/list-idp-groups-in-org` (GET /orgs/{org}/teams/{team_slug}/team-sync/group-mappings)
- `teams/list-child-in-org` (GET /orgs/{org}/teams/{team_slug}/teams)
- `repos/list-teams` (GET /repos/{owner}/{repo}/teams)
- `teams/list-for-authenticated-user` (GET /user/teams)

### Repository collaborators and roles

Each repository's collaborators and their permission, pending repository invitations, custom repository roles, and the organization roles not based on admin with who holds them. The collector reads organization members, administrators, outside collaborators, pending organization invitations, and the holders of each organization role based on admin.

- `orgs/list-custom-repo-roles` (GET /orgs/{org}/custom-repository-roles)
- `orgs/get-custom-repo-role` (GET /orgs/{org}/custom-repository-roles/{role_id})
- `orgs/list-organization-fine-grained-permissions` (GET /orgs/{org}/organization-fine-grained-permissions)
- `orgs/get-org-role` (GET /orgs/{org}/organization-roles/{role_id})
- `orgs/list-org-role-teams` (GET /orgs/{org}/organization-roles/{role_id}/teams)
- `orgs/list-repo-fine-grained-permissions` (GET /orgs/{org}/repository-fine-grained-permissions)
- `repos/list-collaborators` (GET /repos/{owner}/{repo}/collaborators)
- `repos/check-collaborator` (GET /repos/{owner}/{repo}/collaborators/{username})
- `repos/get-collaborator-permission-level` (GET /repos/{owner}/{repo}/collaborators/{username}/permission)
- `repos/list-invitations` (GET /repos/{owner}/{repo}/invitations)
- `repos/list-invitations-for-authenticated-user` (GET /user/repository_invitations)

### Code security configurations

The organization's code security configurations, the repositories each one applies to, and the default configuration for new repositories. The collector reads each repository's code scanning default setup and its open alerts.

- `code-security/get-configurations-for-enterprise` (GET /enterprises/{enterprise}/code-security/configurations)
- `code-security/get-default-configurations-for-enterprise` (GET /enterprises/{enterprise}/code-security/configurations/defaults)
- `code-security/get-single-configuration-for-enterprise` (GET /enterprises/{enterprise}/code-security/configurations/{configuration_id})
- `code-security/get-repositories-for-enterprise-configuration` (GET /enterprises/{enterprise}/code-security/configurations/{configuration_id}/repositories)
- `code-security/get-configurations-for-org` (GET /orgs/{org}/code-security/configurations)
- `code-security/get-default-configurations` (GET /orgs/{org}/code-security/configurations/defaults)
- `code-security/get-configuration` (GET /orgs/{org}/code-security/configurations/{configuration_id})
- `code-security/get-repositories-for-configuration` (GET /orgs/{org}/code-security/configurations/{configuration_id}/repositories)
- `code-security/get-configuration-for-repository` (GET /repos/{owner}/{repo}/code-security-configuration)

### Rulesets and protection beyond the default branch

Protection of branches other than the default branch, the organization's rulesets as a list, rule suite evaluations, and requests to bypass push rules. The collector reads the rules in force on each repository's default branch and the rulesets behind them.

- `orgs/list-push-bypass-requests` (GET /orgs/{org}/bypass-requests/push-rules)
- `repos/get-org-rulesets` (GET /orgs/{org}/rulesets)
- `repos/get-org-rule-suites` (GET /orgs/{org}/rulesets/rule-suites)
- `repos/get-org-rule-suite` (GET /orgs/{org}/rulesets/rule-suites/{rule_suite_id})
- `repos/get-org-ruleset` (GET /orgs/{org}/rulesets/{ruleset_id})
- `orgs/get-org-ruleset-history` (GET /orgs/{org}/rulesets/{ruleset_id}/history)
- `orgs/get-org-ruleset-version` (GET /orgs/{org}/rulesets/{ruleset_id}/history/{version_id})
- `repos/list-branches` (GET /repos/{owner}/{repo}/branches)
- `repos/get-branch` (GET /repos/{owner}/{repo}/branches/{branch})
- `repos/get-branch-protection` (GET /repos/{owner}/{repo}/branches/{branch}/protection)
- `repos/get-admin-branch-protection` (GET /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins)
- `repos/get-pull-request-review-protection` (GET /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews)
- `repos/get-commit-signature-protection` (GET /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures)
- `repos/get-status-checks-protection` (GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks)
- `repos/get-all-status-check-contexts` (GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts)
- `repos/get-access-restrictions` (GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions)
- `repos/get-apps-with-access-to-protected-branch` (GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps)
- `repos/get-teams-with-access-to-protected-branch` (GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams)
- `repos/get-users-with-access-to-protected-branch` (GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users)
- `repos/list-repo-push-bypass-requests` (GET /repos/{owner}/{repo}/bypass-requests/push-rules)
- `repos/get-repo-push-bypass-request` (GET /repos/{owner}/{repo}/bypass-requests/push-rules/{bypass_request_number})
- `repos/get-repo-rulesets` (GET /repos/{owner}/{repo}/rulesets)
- `repos/get-repo-rule-suites` (GET /repos/{owner}/{repo}/rulesets/rule-suites)
- `repos/get-repo-rule-suite` (GET /repos/{owner}/{repo}/rulesets/rule-suites/{rule_suite_id})
- `repos/get-repo-ruleset-history` (GET /repos/{owner}/{repo}/rulesets/{ruleset_id}/history)
- `repos/get-repo-ruleset-version` (GET /repos/{owner}/{repo}/rulesets/{ruleset_id}/history/{version_id})

### Alert management and scanning settings

Requests to dismiss alerts or bypass push protection and who decided them, custom secret scanning patterns and push protection settings, security campaigns, Dependabot's access to private repositories and its runner settings, and whether private vulnerability reporting is enabled. The collector reads each repository's open code scanning, secret scanning and Dependabot alerts, and whether Dependabot alerts, security updates, secret scanning and push protection are on.

- `secret-scanning/list-enterprise-bypass-requests` (GET /enterprises/{enterprise}/bypass-requests/secret-scanning)
- `dependabot/repository-access-for-enterprise` (GET /enterprises/{enterprise}/dependabot/repository-access)
- `secret-scanning/list-enterprise-dismissal-requests` (GET /enterprises/{enterprise}/dismissal-requests/secret-scanning)
- `secret-scanning/list-enterprise-custom-patterns` (GET /enterprises/{enterprise}/secret-scanning/custom-patterns)
- `secret-scanning/list-enterprise-pattern-configs` (GET /enterprises/{enterprise}/secret-scanning/pattern-configurations)
- `secret-scanning/list-org-bypass-requests` (GET /orgs/{org}/bypass-requests/secret-scanning)
- `campaigns/list-org-campaigns` (GET /orgs/{org}/campaigns)
- `campaigns/get-campaign-summary` (GET /orgs/{org}/campaigns/{campaign_number})
- `dependabot/repository-access-for-org` (GET /orgs/{org}/dependabot/repository-access)
- `code-scanning/list-org-dismissal-requests` (GET /orgs/{org}/dismissal-requests/code-scanning)
- `dependabot/list-dismissal-requests-for-org` (GET /orgs/{org}/dismissal-requests/dependabot)
- `secret-scanning/list-org-dismissal-requests` (GET /orgs/{org}/dismissal-requests/secret-scanning)
- `secret-scanning/list-org-custom-patterns` (GET /orgs/{org}/secret-scanning/custom-patterns)
- `secret-scanning/list-org-pattern-configs` (GET /orgs/{org}/secret-scanning/pattern-configurations)
- `secret-scanning/list-repo-bypass-requests` (GET /repos/{owner}/{repo}/bypass-requests/secret-scanning)
- `secret-scanning/get-bypass-request` (GET /repos/{owner}/{repo}/bypass-requests/secret-scanning/{bypass_request_number})
- `dependabot/get-repository-runner-settings` (GET /repos/{owner}/{repo}/dependabot/runner-settings)
- `code-scanning/list-dismissal-requests-for-repo` (GET /repos/{owner}/{repo}/dismissal-requests/code-scanning)
- `code-scanning/get-dismissal-request-for-repo` (GET /repos/{owner}/{repo}/dismissal-requests/code-scanning/{alert_number})
- `dependabot/list-dismissal-requests-for-repo` (GET /repos/{owner}/{repo}/dismissal-requests/dependabot)
- `dependabot/get-dismissal-request-for-repo` (GET /repos/{owner}/{repo}/dismissal-requests/dependabot/{alert_number})
- `secret-scanning/list-repo-dismissal-requests` (GET /repos/{owner}/{repo}/dismissal-requests/secret-scanning)
- `secret-scanning/get-dismissal-request` (GET /repos/{owner}/{repo}/dismissal-requests/secret-scanning/{alert_number})
- `repos/check-private-vulnerability-reporting` (GET /repos/{owner}/{repo}/private-vulnerability-reporting)
- `secret-scanning/list-repo-custom-patterns` (GET /repos/{owner}/{repo}/secret-scanning/custom-patterns)

### Credentials authorized for SAML single sign-on, and provisioned identities

For an organization that uses SAML single sign-on, the identities provisioned through SCIM with their identity provider attributes, and the personal access tokens, SSH keys and OAuth app tokens that members have authorized for single sign-on. The credentials the collector counts are fine-grained personal access tokens and deploy keys.

- `orgs/list-saml-sso-authorizations` (GET /orgs/{org}/credential-authorizations)
- `scim/list-provisioned-identities` (GET /scim/v2/organizations/{org}/Users)
- `scim/get-provisioning-information-for-user` (GET /scim/v2/organizations/{org}/Users/{scim_user_id})

### Personal access token requests and repository access

Pending requests for fine-grained personal access tokens, and the repositories each granted token can reach. The collector lists the granted tokens.

- `orgs/list-pat-grant-requests` (GET /orgs/{org}/personal-access-token-requests)
- `orgs/list-pat-grant-request-repositories` (GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories)
- `orgs/list-pat-grant-repositories` (GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories)

### Artifact attestations, immutable releases and custom properties

Artifact attestations and artifact metadata, whether releases are immutable, and the custom properties defined for the organization and set on each repository, which rulesets can target.

- `orgs/custom-properties-for-orgs-get-organization-values` (GET /organizations/{org}/org-properties/values)
- `orgs/get-cluster-deployment-records-job` (GET /orgs/{org}/artifacts/metadata/deployment-record/cluster/{cluster}/jobs/{job_id})
- `orgs/list-artifact-deployment-records` (GET /orgs/{org}/artifacts/{subject_digest}/metadata/deployment-records)
- `orgs/list-artifact-storage-records` (GET /orgs/{org}/artifacts/{subject_digest}/metadata/storage-records)
- `orgs/list-attestation-repositories` (GET /orgs/{org}/attestations/repositories)
- `orgs/list-attestations` (GET /orgs/{org}/attestations/{subject_digest})
- `orgs/external-properties-for-repos-get-organization-app-installations` (GET /orgs/{org}/properties/installations)
- `orgs/external-properties-for-repos-get-organization-definitions` (GET /orgs/{org}/properties/installations/schema)
- `orgs/custom-properties-for-repos-get-organization-definitions` (GET /orgs/{org}/properties/schema)
- `orgs/custom-properties-for-repos-get-organization-definition` (GET /orgs/{org}/properties/schema/{custom_property_name})
- `orgs/custom-properties-for-repos-get-organization-values` (GET /orgs/{org}/properties/values)
- `orgs/get-immutable-releases-settings` (GET /orgs/{org}/settings/immutable-releases)
- `orgs/get-immutable-releases-settings-repositories` (GET /orgs/{org}/settings/immutable-releases/repositories)
- `repos/list-attestations` (GET /repos/{owner}/{repo}/attestations/{subject_digest})
- `repos/check-immutable-releases` (GET /repos/{owner}/{repo}/immutable-releases)
- `repos/custom-properties-for-repos-get-repository-values` (GET /repos/{owner}/{repo}/properties/values)
- `users/list-attestations` (GET /users/{username}/attestations/{subject_digest})

### Members' public keys

Members' public SSH keys, GPG keys and SSH signing keys.

- `users/list-gpg-keys-for-authenticated-user` (GET /user/gpg_keys)
- `users/get-gpg-key-for-authenticated-user` (GET /user/gpg_keys/{gpg_key_id})
- `users/list-public-ssh-keys-for-authenticated-user` (GET /user/keys)
- `users/get-public-ssh-key-for-authenticated-user` (GET /user/keys/{key_id})
- `users/list-ssh-signing-keys-for-authenticated-user` (GET /user/ssh_signing_keys)
- `users/get-ssh-signing-key-for-authenticated-user` (GET /user/ssh_signing_keys/{ssh_signing_key_id})
- `users/list-gpg-keys-for-user` (GET /users/{username}/gpg_keys)
- `users/list-public-keys-for-user` (GET /users/{username}/keys)
- `users/list-ssh-signing-keys-for-user` (GET /users/{username}/ssh_signing_keys)

### Pages

Whether a repository publishes a GitHub Pages site, with its visibility, custom domain and HTTPS enforcement.

- `repos/get-pages` (GET /repos/{owner}/{repo}/pages)
- `repos/list-pages-builds` (GET /repos/{owner}/{repo}/pages/builds)
- `repos/get-latest-pages-build` (GET /repos/{owner}/{repo}/pages/builds/latest)
- `repos/get-pages-build` (GET /repos/{owner}/{repo}/pages/builds/{build_id})
- `repos/get-pages-deployment` (GET /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id})
- `repos/get-pages-health-check` (GET /repos/{owner}/{repo}/pages/health)

### Repository security advisories

Security advisories published for a repository, and the vulnerability reports it received privately.

- `security-advisories/list-org-repository-advisories` (GET /orgs/{org}/security-advisories)
- `security-advisories/list-repository-advisories` (GET /repos/{owner}/{repo}/security-advisories)
- `security-advisories/get-repository-advisory` (GET /repos/{owner}/{repo}/security-advisories/{ghsa_id})
- `security-advisories/list-repository-advisory-comments` (GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments)
- `security-advisories/get-repository-advisory-comment` (GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments/{comment_id})

### Enterprise settings

Settings of the enterprise that owns the organization: enterprise roles and who holds them, the enterprise audit log and its streaming, SCIM provisioning, the token inventory, custom properties, network configurations, AI controls and licensing. The collector reads one organization.

- `enterprise-admin/get-server-statistics` (GET /enterprise-installation/{enterprise_or_org}/server-statistics)
- `announcement-banners/get-announcement-banner-for-enterprise` (GET /enterprises/{enterprise}/announcement)
- `enterprise-apps/installable-organizations` (GET /enterprises/{enterprise}/apps/installable_organizations)
- `enterprise-apps/installable-organization-accessible-repositories` (GET /enterprises/{enterprise}/apps/installable_organizations/{org}/accessible_repositories)
- `enterprise-apps/organization-installations` (GET /enterprises/{enterprise}/apps/organizations/{org}/installations)
- `enterprise-apps/organization-installation-repositories` (GET /enterprises/{enterprise}/apps/organizations/{org}/installations/{installation_id}/repositories)
- `enterprise-admin/get-audit-log` (GET /enterprises/{enterprise}/audit-log)
- `enterprise-admin/get-audit-log-stream-key` (GET /enterprises/{enterprise}/audit-log/stream-key)
- `enterprise-admin/get-audit-log-streams` (GET /enterprises/{enterprise}/audit-log/streams)
- `enterprise-admin/get-one-audit-log-stream` (GET /enterprises/{enterprise}/audit-log/streams/{stream_id})
- `enterprise-admin/list-push-bypass-requests` (GET /enterprises/{enterprise}/bypass-requests/push-rules)
- `enterprise-admin/get-consumed-licenses` (GET /enterprises/{enterprise}/consumed-licenses)
- `enterprise-admin/get-enterprise-apps-model-policies` (GET /enterprises/{enterprise}/copilot/apps/model-policies)
- `enterprise-admin/get-enterprise-feature-policies` (GET /enterprises/{enterprise}/copilot/feature-policies)
- `enterprise-admin/get-enterprise-fusion-model-policies` (GET /enterprises/{enterprise}/copilot/fusion/model-policies)
- `enterprise-admin/get-enterprise-model-policies` (GET /enterprises/{enterprise}/copilot/model-policies)
- `enterprise-admin/get-enterprise-token-inventory-export` (GET /enterprises/{enterprise}/credentials/exports/{export_id})
- `enterprise-admin/list-enterprise-roles` (GET /enterprises/{enterprise}/enterprise-roles)
- `enterprise-admin/get-enterprise-role` (GET /enterprises/{enterprise}/enterprise-roles/{role_id})
- `enterprise-admin/list-enterprise-role-teams` (GET /enterprises/{enterprise}/enterprise-roles/{role_id}/teams)
- `enterprise-admin/list-enterprise-role-users` (GET /enterprises/{enterprise}/enterprise-roles/{role_id}/users)
- `enterprise-admin/get-enterprise-innersource-vulnerability-sync-status` (GET /enterprises/{enterprise}/innersource-vulnerabilities/sync/status/{job_id})
- `enterprise-admin/get-license-sync-status` (GET /enterprises/{enterprise}/license-sync-status)
- `enterprise-team-memberships/list-teams-for-user` (GET /enterprises/{enterprise}/members/{username}/teams)
- `hosted-compute/list-network-configurations-for-enterprise` (GET /enterprises/{enterprise}/network-configurations)
- `hosted-compute/get-network-configuration-for-enterprise` (GET /enterprises/{enterprise}/network-configurations/{network_configuration_id})
- `hosted-compute/get-network-settings-for-enterprise` (GET /enterprises/{enterprise}/network-settings/{network_settings_id})
- `enterprise-admin/custom-properties-for-orgs-get-enterprise-definitions` (GET /enterprises/{enterprise}/org-properties/schema)
- `enterprise-admin/custom-properties-for-orgs-get-enterprise-definition` (GET /enterprises/{enterprise}/org-properties/schema/{custom_property_name})
- `enterprise-admin/custom-properties-for-orgs-get-enterprise-values` (GET /enterprises/{enterprise}/org-properties/values)
- `enterprise-admin/custom-properties-for-repos-get-enterprise-definitions` (GET /enterprises/{enterprise}/properties/schema)
- `enterprise-admin/custom-properties-for-repos-get-enterprise-definition` (GET /enterprises/{enterprise}/properties/schema/{custom_property_name})
- `repos/get-enterprise-ruleset` (GET /enterprises/{enterprise}/rulesets/{ruleset_id})
- `enterprise-admin/get-enterprise-ruleset-history` (GET /enterprises/{enterprise}/rulesets/{ruleset_id}/history)
- `enterprise-admin/get-enterprise-ruleset-version` (GET /enterprises/{enterprise}/rulesets/{ruleset_id}/history/{version_id})
- `billing/get-github-advanced-security-billing-ghe` (GET /enterprises/{enterprise}/settings/billing/advanced-security)
- `enterprise-teams/list` (GET /enterprises/{enterprise}/teams)
- `enterprise-team-memberships/list` (GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships)
- `enterprise-team-memberships/get` (GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships/{username})
- `enterprise-team-organizations/get-assignments` (GET /enterprises/{enterprise}/teams/{enterprise-team}/organizations)
- `enterprise-team-organizations/get-assignment` (GET /enterprises/{enterprise}/teams/{enterprise-team}/organizations/{org})
- `enterprise-admin/get-enterprise-team-model-policies` (GET /enterprises/{enterprise}/teams/{team_id}/copilot/model-policies)
- `enterprise-teams/get` (GET /enterprises/{enterprise}/teams/{team_slug})
- `enterprise-admin/list-vss` (GET /enterprises/{enterprise}/visual-studio-subscriptions)
- `enterprise-admin/list-provisioned-groups-enterprise` (GET /scim/v2/enterprises/{enterprise}/Groups)
- `enterprise-admin/get-provisioning-information-for-enterprise-group` (GET /scim/v2/enterprises/{enterprise}/Groups/{scim_group_id})
- `enterprise-admin/list-provisioned-identities-enterprise` (GET /scim/v2/enterprises/{enterprise}/Users)
- `enterprise-admin/get-provisioning-information-for-enterprise-user` (GET /scim/v2/enterprises/{enterprise}/Users/{scim_user_id})

### IP allow list

Whether the organization has an IP allow list enabled, and the allowed addresses. GitHub exposes these through its GraphQL API.

## Calls the sandbox never exercises

The collector makes these calls when the tenant has something the sandbox lacks, so no recording holds them.

- `orgs/list-org-roles` (GET /orgs/{org}/organization-roles): github.org_roles.list, when the members' base permission is below admin; the recordings predate this read.
- `orgs/list-org-role-users` (GET /orgs/{org}/organization-roles/{role_id}/users): github.org_role_users.list, when an organization role is based on admin; the recordings predate this read.
- `repos/list-deployment-branch-policies` (GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies): github.environment_branch_policies.list, when an environment limits deployments to selected branches.
- `repos/get-all-deployment-protection-rules` (GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules): github.environment_protection_rules.list, when an environment has a custom deployment protection rule.
- `users/get-by-username` (GET /users/{username}): github.users.get, when a member's display name is not in the GraphQL result.
- github.saml_identities.list, when the organization uses SAML single sign-on; a GraphQL query, outside the REST description.

## Left out as irrelevant

- **Workflow execution data and runner detail, not configuration.** `actions/get-actions-cache-retention-limit-for-enterprise`, `actions/get-actions-cache-storage-limit-for-enterprise`, `actions/get-actions-cache-usage-for-enterprise`, `actions/list-hosted-runners-for-enterprise`, `actions/list-custom-images-for-enterprise`, `actions/get-custom-image-for-enterprise`, `actions/list-custom-image-versions-for-enterprise`, `actions/get-custom-image-version-for-enterprise`, `actions/get-hosted-runners-github-owned-images-for-enterprise`, `actions/get-hosted-runners-partner-images-for-enterprise`, `actions/get-hosted-runners-limits-for-enterprise`, `actions/get-hosted-runners-machine-specs-for-enterprise`, `actions/get-hosted-runners-platforms-for-enterprise`, `actions/get-hosted-runner-for-enterprise`, `enterprise-admin/list-self-hosted-runners-for-enterprise`, `enterprise-admin/get-runner-version-deprecation-for-enterprise`, `enterprise-admin/list-runner-applications-for-enterprise`, `enterprise-admin/get-self-hosted-runner-for-enterprise`, `enterprise-admin/list-labels-for-self-hosted-runner-for-enterprise`, `actions/get-actions-cache-retention-limit-for-organization`, `actions/get-actions-cache-storage-limit-for-organization`, `actions/get-actions-cache-usage-for-org`, `actions/get-actions-cache-usage-by-repo-for-org`, `actions/list-hosted-runners-for-org`, `actions/list-custom-images-for-org`, `actions/get-custom-image-for-org`, `actions/list-custom-image-versions-for-org`, `actions/get-custom-image-version-for-org`, `actions/get-hosted-runners-github-owned-images-for-org`, `actions/get-hosted-runners-partner-images-for-org`, `actions/get-hosted-runners-limits-for-org`, `actions/get-hosted-runners-machine-specs-for-org`, `actions/get-hosted-runners-platforms-for-org`, `actions/get-hosted-runner-for-org`, `actions/get-runner-version-deprecation-for-org`, `actions/list-runner-applications-for-org`, `actions/get-self-hosted-runner-for-org`, `actions/list-labels-for-self-hosted-runner-for-org`, `actions/list-artifacts-for-repo`, `actions/get-artifact`, `actions/download-artifact`, `actions/get-actions-cache-retention-limit-for-repository`, `actions/get-actions-cache-storage-limit-for-repository`, `actions/get-actions-cache-usage`, `actions/get-actions-cache-list`, `actions/list-concurrency-groups-for-repository`, `actions/get-concurrency-group-for-repository`, `actions/get-job-for-workflow-run`, `actions/download-job-logs-for-workflow-run`, `actions/download-step-logs-for-workflow-run-job`, `actions/get-runner-version-deprecation-for-repo`, `actions/list-runner-applications-for-repo`, `actions/get-self-hosted-runner-for-repo`, `actions/list-labels-for-self-hosted-runner-for-repo`, `actions/list-workflow-runs-for-repo`, `actions/get-workflow-run`, `actions/get-reviews-for-run`, `actions/list-workflow-run-artifacts`, `actions/get-workflow-run-attempt`, `actions/list-jobs-for-workflow-run-attempt`, `actions/download-workflow-run-attempt-logs`, `actions/list-concurrency-groups-for-workflow-run`, `actions/list-jobs-for-workflow-run`, `actions/download-workflow-run-logs`, `actions/get-pending-deployments-for-run`, `actions/get-workflow-run-usage`, `actions/list-repo-workflows`, `actions/get-workflow`, `actions/list-workflow-runs`, `actions/get-workflow-usage`, `checks/get`, `checks/list-annotations`, `checks/get-suite`, `checks/list-for-suite`, `checks/list-for-ref`, `checks/list-suites-for-ref`
- **Code, issues, pull requests, projects and other content.** `meta/root`, `agent-merge/get-agent-merge-enrollment`, `codes-of-conduct/get-all-codes-of-conduct`, `codes-of-conduct/get-conduct-code`, `emojis/get`, `dependency-graph/get-enterprise-license-policy`, `activity/list-public-events`, `activity/get-feeds`, `gists/list`, `gists/list-public`, `gists/list-starred`, `gists/get`, `gists/list-comments`, `gists/get-comment`, `gists/list-commits`, `gists/list-forks`, `gists/check-is-starred`, `gists/get-revision`, `gitignore/get-all-templates`, `gitignore/get-template`, `issues/list`, `licenses/get-all-commonly-used`, `licenses/get`, `meta/get`, `activity/list-public-events-for-repo-network`, `activity/list-notifications-for-authenticated-user`, `activity/get-thread`, `activity/get-thread-subscription-for-authenticated-user`, `meta/get-octocat`, `packages/list-docker-migration-conflicting-packages-for-organization`, `activity/list-public-org-events`, `interactions/get-restrictions-for-org`, `interactions/get-pull-request-creation-cap-for-org`, `orgs/list-issue-fields`, `orgs/list-issue-types`, `issues/list-for-org`, `migrations/list-for-org`, `migrations/get-status-for-org`, `migrations/download-archive-for-org`, `migrations/list-repos-for-org`, `packages/list-packages-for-organization`, `packages/get-package-for-organization`, `packages/get-all-package-versions-for-package-owned-by-org`, `packages/get-package-version-for-organization`, `projects/list-for-org`, `projects/get-for-org`, `projects/list-fields-for-org`, `projects/get-field-for-org`, `projects/list-items-for-org`, `projects/get-org-item`, `projects/list-view-items-for-org`, `rate-limit/get`, `issues/list-assignees`, `issues/check-user-can-be-assigned`, `repos/list-autolinks`, `repos/get-autolink`, `code-quality/list-findings-for-repo`, `code-quality/get-finding`, `code-quality/get-setup`, `repos/list-commit-comments-for-repo`, `repos/get-commit-comment`, `reactions/list-for-commit-comment`, `repos/list-commits`, `repos/list-branches-for-head-commit`, `repos/list-comments-for-commit`, `repos/list-pull-requests-associated-with-commit`, `repos/get-commit`, `repos/get-combined-status-for-ref`, `repos/list-commit-statuses-for-ref`, `repos/get-community-profile-metrics`, `repos/compare-commits`, `dependency-graph/diff-range`, `dependency-graph/fetch-sbom-report`, `dependency-graph/generate-sbom-report`, `activity/list-repo-events`, `repos/list-forks`, `git/get-blob`, `git/get-commit`, `git/list-matching-refs`, `git/get-ref`, `git/get-tag`, `git/get-tree`, `interactions/get-restrictions-for-repo`, `interactions/get-pull-request-bypass-list-for-repo`, `interactions/get-pull-request-creation-cap-for-repo`, `repos/list-issue-types`, `issues/list-for-repo`, `issues/list-comments-for-repo`, `issues/get-comment`, `reactions/list-for-issue-comment`, `issues/list-events-for-repo`, `issues/get-event`, `issues/get`, `issues/list-issue-artifacts`, `issues/get-issue-artifact`, `issues/check-user-can-be-assigned-to-issue`, `issues/list-comments`, `issues/list-dependencies-blocked-by`, `issues/list-dependencies-blocking`, `issues/list-events`, `issues/list-issue-field-values-for-issue`, `issues/list-labels-on-issue`, `issues/get-parent`, `reactions/list-for-issue`, `issues/list-relates-to`, `issues/list-sub-issues`, `issues/list-suggestions`, `issues/list-events-for-timeline`, `issues/list-labels-for-repo`, `issues/get-label`, `licenses/get-for-repo`, `issues/list-milestones`, `issues/get-milestone`, `issues/list-labels-for-milestone`, `activity/list-repo-notifications-for-authenticated-user`, `pulls/list`, `pulls/list-review-comments-for-repo`, `pulls/get-review-comment`, `reactions/list-for-pull-request-review-comment`, `pulls/get`, `pulls/list-review-comments`, `pulls/list-commits`, `pulls/list-files`, `pulls/check-if-merged`, `pulls/get-merge-async-result`, `pulls/list-requested-reviewers`, `pulls/list-reviews`, `pulls/get-review`, `pulls/list-comments-for-review`, `repos/get-readme`, `repos/get-readme-in-directory`, `repos/list-releases`, `repos/get-release-asset`, `repos/get-latest-release`, `repos/get-release-by-tag`, `repos/get-release`, `repos/list-release-assets`, `reactions/list-for-release`, `pull-request-stacks/list`, `pull-request-stacks/get`, `activity/list-stargazers-for-repo`, `activity/get-stargazer-count-for-repo`, `activity/get-stargazer-history-for-repo`, `repos/get-code-frequency-stats`, `repos/get-commit-activity-stats`, `repos/get-contributors-stats`, `repos/get-participation-stats`, `repos/get-punch-card-stats`, `activity/list-watchers-for-repo`, `activity/get-repo-subscription`, `repos/download-tarball-archive`, `repos/get-clones`, `repos/get-top-paths`, `repos/get-top-referrers`, `repos/get-views`, `repos/download-zipball-archive`, `search/code`, `search/commits`, `search/issues-and-pull-requests`, `search/labels`, `search/repos`, `search/topics`, `search/users`, `packages/list-docker-migration-conflicting-packages-for-authenticated-user`, `interactions/get-restrictions-for-authenticated-user`, `users/list-issue-fields-for-authenticated-user`, `users/list-issue-types-for-authenticated-user`, `issues/list-for-authenticated-user`, `migrations/list-for-authenticated-user`, `migrations/get-status-for-authenticated-user`, `migrations/get-archive-for-authenticated-user`, `migrations/list-repos-for-authenticated-user`, `packages/list-packages-for-authenticated-user`, `packages/get-package-for-authenticated-user`, `packages/get-all-package-versions-for-package-owned-by-authenticated-user`, `packages/get-package-version-for-authenticated-user`, `activity/list-repos-starred-by-authenticated-user`, `activity/check-repo-is-starred-by-authenticated-user`, `activity/list-watched-repos-for-authenticated-user`, `packages/list-docker-migration-conflicting-packages-for-user`, `activity/list-events-for-authenticated-user`, `activity/list-org-events-for-authenticated-user`, `activity/list-public-events-for-user`, `gists/list-for-user`, `packages/list-packages-for-user`, `packages/get-package-for-user`, `packages/get-all-package-versions-for-package-owned-by-user`, `packages/get-package-version-for-user`, `projects/list-for-user`, `projects/get-for-user`, `projects/list-fields-for-user`, `projects/get-field-for-user`, `projects/list-items-for-user`, `projects/get-user-item`, `projects/list-view-items-for-user`, `activity/list-received-events-for-user`, `activity/list-received-public-events-for-user`, `activity/list-repos-starred-by-user`, `activity/list-repos-watched-by-user`, `meta/get-all-versions`, `meta/get-zen`
- **Social and profile data.** `orgs/list-blocked-users`, `orgs/check-blocked-user`, `users/get-authenticated`, `users/list-blocked-by-authenticated-user`, `users/check-blocked`, `users/list-emails-for-authenticated-user`, `users/list-followers-for-authenticated-user`, `users/list-followed-by-authenticated-user`, `users/check-person-is-followed-by-authenticated`, `users/list-public-emails-for-authenticated-user`, `users/list-social-accounts-for-authenticated-user`, `users/get-by-id`, `users/list`, `users/list-followers-for-user`, `users/list-following-for-user`, `users/check-following-for-user`, `users/get-context-for-user`, `users/list-social-accounts-for-user`
- **Copilot and AI agents, which are usage rather than security posture.** `agent-automations/list-automations`, `agent-automations/list-repo-automations`, `agent-automations/list-available-repo-automation-tools`, `agent-automations/list-available-repo-automation-triggers`, `agent-automations/get-repo-automation`, `agent-automations/list-automation-revisions`, `agent-automations/get-automation-revision`, `agent-automations/list-repo-automation-tasks`, `agent-tasks/list-tasks-for-repo`, `agent-tasks/get-task-by-repo-and-id`, `agent-tasks/list-tasks`, `agent-tasks/get-task-by-id`, `copilot/list-copilot-seats-for-enterprise`, `copilot/copilot-content-exclusion-for-enterprise`, `copilot/get-copilot-custom-agents-for-enterprise`, `copilot/get-copilot-custom-agents-source-for-enterprise`, `copilot/copilot-enterprise-one-day-usage-metrics`, `copilot/copilot-enterprise-usage-metrics`, `copilot/copilot-enterprise-repos-one-day-report`, `copilot/copilot-enterprise-user-teams-one-day-report`, `copilot/copilot-users-one-day-usage-metrics`, `copilot/copilot-users-usage-metrics`, `copilot/get-enterprise-code-review-policy`, `copilot/get-usage-records`, `copilot/get-copilot-seat-details-for-enterprise-user`, `copilot-spaces/list-for-org`, `copilot-spaces/get-for-org`, `copilot-spaces/list-collaborators-for-org`, `copilot-spaces/list-resources-for-org`, `copilot-spaces/get-resource-for-org`, `copilot/get-copilot-organization-details`, `copilot/list-copilot-seats`, `copilot/get-organization-code-review-runner`, `copilot/get-organization-code-review-settings`, `copilot/get-copilot-coding-agent-permissions-organization`, `copilot/list-copilot-coding-agent-selected-repositories-for-organization`, `copilot/copilot-content-exclusion-for-organization`, `copilot/get-organization-feature-policies`, `copilot/copilot-organization-one-day-usage-metrics`, `copilot/copilot-organization-usage-metrics`, `copilot/copilot-organization-repos-one-day-report`, `copilot/copilot-organization-user-teams-one-day-report`, `copilot/copilot-organization-users-one-day-usage-metrics`, `copilot/copilot-organization-users-usage-metrics`, `copilot/get-organization-model-policies`, `copilot/get-organization-code-review-policy`, `copilot/get-copilot-seat-details-for-user`, `copilot/get-copilot-team-customizations`, `copilot/get-copilot-cloud-agent-configuration`, `copilot/get-repository-code-review-settings`, `copilot-spaces/list-for-user`, `copilot-spaces/get-for-user`, `copilot-spaces/list-collaborators-for-user`, `copilot-spaces/list-resources-for-user`, `copilot-spaces/get-resource-for-user`
- **Billing and usage.** `billing/get-github-billing-ai-credit-usage-report-ghe`, `billing/get-all-budgets`, `billing/get-budget`, `billing/get-budget-user-states`, `billing/get-all-cost-centers`, `billing/get-cost-center-membership`, `billing/get-cost-center`, `billing/get-github-billing-premium-request-usage-report-ghe`, `billing/list-usage-report-exports`, `billing/get-usage-report-export`, `billing/get-github-billing-usage-report-ghe`, `billing/get-github-billing-usage-summary-report-ghe`, `api-insights/get-route-stats-by-actor`, `api-insights/get-subject-stats`, `api-insights/get-summary-stats`, `api-insights/get-summary-stats-by-user`, `api-insights/get-summary-stats-by-actor`, `api-insights/get-time-stats`, `api-insights/get-time-stats-by-user`, `api-insights/get-time-stats-by-actor`, `api-insights/get-user-stats`, `billing/get-github-advanced-security-billing-org`
- **The collector's own GitHub App, and the marketplace.** `apps/get-authenticated`, `apps/get-webhook-config-for-app`, `apps/list-webhook-deliveries`, `apps/get-webhook-delivery`, `apps/list-installation-requests-for-authenticated-app`, `apps/list-installations`, `apps/get-installation`, `apps/get-by-slug`, `apps/get-enterprise-installation`, `apps/get-subscription-plan-for-account`, `apps/list-plans`, `apps/list-accounts-for-plan`, `apps/get-subscription-plan-for-account-stubbed`, `apps/list-plans-stubbed`, `apps/list-accounts-for-plan-stubbed`, `apps/get-org-installation`, `apps/get-repo-installation`, `apps/list-installations-for-authenticated-user`, `apps/list-installation-repos-for-authenticated-user`, `apps/list-subscriptions-for-authenticated-user`, `apps/list-subscriptions-for-authenticated-user-stubbed`, `apps/get-user-installation`
- **Detail of, or another view on, what the collector already reads.** `security-advisories/list-global-advisories`, `security-advisories/get-global-advisory`, `code-scanning/list-alerts-for-enterprise`, `dependabot/list-alerts-for-enterprise`, `secret-scanning/list-alerts-for-enterprise`, `secret-scanning/list-public-monitoring-alerts-for-enterprise`, `secret-scanning/get-public-monitoring-alert-for-enterprise`, `orgs/list`, `announcement-banners/get-announcement-banner-for-org`, `code-scanning/get-ai-scan-enablement-for-org`, `code-scanning/list-alerts-for-org`, `codespaces/list-in-organization`, `dependabot/list-alerts-for-org`, `orgs/list-failed-invitations`, `orgs/get-webhook`, `orgs/get-webhook-config-for-org`, `orgs/list-webhook-deliveries`, `orgs/get-webhook-delivery`, `orgs/list-invitation-teams`, `orgs/check-membership-for-user`, `codespaces/get-codespaces-for-user-in-org`, `orgs/get-membership-for-user`, `orgs/list-public-members`, `orgs/check-public-membership-for-user`, `repos/list-for-org`, `secret-scanning/list-alerts-for-org`, `repos/list-activities`, `repos/check-automated-security-fixes`, `code-scanning/get-ai-scan-enablement`, `code-scanning/get-alert`, `code-scanning/get-autofix`, `code-scanning/list-alert-instances`, `code-scanning/get-analysis`, `code-scanning/list-codeql-databases`, `code-scanning/get-codeql-database`, `code-scanning/get-variant-analysis`, `code-scanning/get-variant-analysis-repo-task`, `code-scanning/get-sarif`, `repos/codeowners-errors`, `codespaces/list-in-repository-for-authenticated-user`, `codespaces/list-devcontainers-in-repository-for-authenticated-user`, `codespaces/repo-machines-for-authenticated-user`, `codespaces/pre-flight-with-repo-for-authenticated-user`, `codespaces/check-permissions-for-devcontainer`, `repos/list-contributors`, `dependabot/get-alert`, `repos/list-deployments`, `repos/get-deployment`, `repos/list-deployment-statuses`, `repos/get-deployment-status`, `repos/get-environment`, `repos/get-deployment-branch-policy`, `repos/list-custom-deployment-rule-integrations`, `repos/get-custom-deployment-protection-rule`, `repos/get-hash-algorithm`, `repos/get-webhook`, `repos/get-webhook-config-for-repo`, `repos/list-webhook-deliveries`, `repos/get-webhook-delivery`, `repos/get-deploy-key`, `repos/list-languages`, `secret-scanning/get-alert`, `secret-scanning/list-locations-for-alert`, `secret-scanning/get-scan-history`, `repos/list-tags`, `repos/get-all-topics`, `repos/check-vulnerability-alerts`, `repos/list-public`, `codespaces/list-for-authenticated-user`, `codespaces/get-for-authenticated-user`, `codespaces/get-export-details-for-authenticated-user`, `codespaces/codespace-machines-for-authenticated-user`, `orgs/list-memberships-for-authenticated-user`, `orgs/get-membership-for-authenticated-user`, `orgs/list-for-authenticated-user`, `repos/list-for-authenticated-user`, `orgs/list-for-user`, `repos/list-for-user`

## Outside the description

- github.member_names.list (POST /graphql): A GraphQL query, which the REST API description does not cover
- github.repositories.list (POST /graphql): A GraphQL query, which the REST API description does not cover

Generated by `epack sdk surface` from `docs/surface.yaml` and the collector's recordings. Edit the verdicts there, then run `epack sdk surface --write`.
