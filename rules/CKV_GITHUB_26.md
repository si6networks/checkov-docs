# CKV_GITHUB_26: Ensure minimum admins are set for the organization
## Severity
**HIGH** (score: 7.0/10)

An excessive number of organization admins expands the attack surface for privileged account compromise, since any one of many admin accounts can take over the entire organization.

## Summary
This check enforces that a GitHub organization has no more than 3 members holding the organization Owner/admin role, based on the organization's admin membership list.

## Applicability
**Checkov framework(s):** `github_configuration`

Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated specifically against a configuration document whose file name contains `org_admins` (the exported list of organization owners/admins), validated against the `org_members` schema.

## Why it matters
Organization owners have unrestricted power: they can delete any repository, modify billing, change security policies (including disabling 2FA or SSO enforcement), add or remove other owners, and access every private repository in the org. Every additional owner account is an additional full-compromise target — if any one owner's credentials are phished or their account is otherwise taken over, the attacker gains total control of the organization. This check enforces the security principle of least privilege / minimizing the admin attack surface by capping the admin count at 3, which is enough for redundancy (avoiding a single point of failure/bus-factor problem) without unnecessarily multiplying high-privilege accounts.

## How Checkov evaluates this
The check only evaluates configuration whose `file_name` metadata contains the string `org_admins`; otherwise it returns UNKNOWN. It validates the configuration list against the `org_members` schema, then counts the entries (`len(conf)`). If the count of admins is less than or equal to `MAX_ADMIN_COUNT = 3`, the check PASSES; if there are more than 3 admins, it FAILS.

## Non-compliant example
```json
[
  { "login": "alice", "role": "admin" },
  { "login": "bob", "role": "admin" },
  { "login": "carol", "role": "admin" },
  { "login": "dave", "role": "admin" }
]
```

## Remediated example
```json
[
  { "login": "alice", "role": "admin" },
  { "login": "bob", "role": "admin" },
  { "login": "carol", "role": "admin" }
]
```

## Remediation steps
1. Review your GitHub organization's People page filtered by role "Owner" (Settings > People).
2. Downgrade owners who don't strictly need full organizational control to "Member" role, granting them team- or repository-level admin permissions instead where appropriate.
3. Keep the owner count at 3 or fewer — ideally an odd/small number sufficient for redundancy and emergency access, but no more.
4. Enforce MFA/hardware security keys for all remaining owners, since they represent the highest-value targets in the organization.
5. Establish a periodic (e.g., quarterly) access review of the owners list to prevent silent creep back above the threshold.
6. Re-run the Checkov GitHub scan against the exported `org_admins` data to confirm the count is at or below 3.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/minimum_admins_in_org.py)
- [GitHub Docs: Roles in an organization](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization)
