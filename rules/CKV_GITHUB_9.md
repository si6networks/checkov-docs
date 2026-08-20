# CKV_GITHUB_9: Ensure 2 admins are set for each repository
## Severity
**MEDIUM** (score: 4.5/10)

Relying on a single repository admin creates a single point of failure for incident response and access recovery if that one admin account is compromised or unavailable.

## Summary
This check enforces that a GitHub repository has at least two collaborators with admin permission, avoiding a single point of failure/control over the repository.

## Applicability
Applies to GitHub organization/repository configuration (`github_configuration` IaC type, entity `*`), evaluated against the repository collaborators document (files matching `repository_collaborators`), where each collaborator entry has a `permissions` object with an `admin` boolean.

## Why it matters
If only one person holds admin rights on a repository, that individual becomes both a single point of failure (if they leave the company, lose access, or are unavailable during an incident, nobody can promptly manage branch protection, secrets, or access settings) and a single point of compromise (an attacker who takes over that one admin account gets unchecked control of the repository — deleting it, rewriting protection rules, exfiltrating secrets, or adding malicious collaborators — with no other admin around to notice or intervene quickly). Requiring at least two admins builds in redundancy for both availability (bus-factor) and security oversight (a second set of eyes / recovery path), similar in spirit to two-person integrity controls elsewhere in the org.

## How Checkov evaluates this
For a repository's collaborators list, the check counts how many collaborator entries have `permissions.admin == True`. If that count is 2 or more, the check PASSES; if fewer than 2 (0 or 1 admins), it FAILS. If the configuration doesn't correspond to a `repository_collaborators` file or doesn't validate against the expected schema, the result is UNKNOWN.

## Non-compliant example
```json
[
  { "login": "alice", "permissions": { "admin": true, "push": true, "pull": true } },
  { "login": "bob", "permissions": { "admin": false, "push": true, "pull": true } }
]
```

## Remediated example
```json
[
  { "login": "alice", "permissions": { "admin": true, "push": true, "pull": true } },
  { "login": "bob", "permissions": { "admin": true, "push": true, "pull": true } }
]
```

## Remediation steps
1. Go to the repository's Settings > Collaborators and teams.
2. Grant admin permission to at least one additional trusted collaborator or team beyond the current sole admin.
3. Prefer granting admin via a team (e.g., a "repo-admins" team) rather than individual accounts, so membership changes (onboarding/offboarding) automatically keep the admin count correct.
4. Avoid over-granting admin — keep the count intentionally small (2 is the enforced minimum; don't multiply this unnecessarily across dozens of accounts).
5. Re-run the Checkov GitHub scan against the exported `repository_collaborators` data to confirm at least 2 admins are present.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/repository_collaborators.py)
- [GitHub Docs: Repository roles for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/repository-roles-for-an-organization)
