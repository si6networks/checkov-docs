# CKV_GITHUB_27: Ensure strict base permissions are set for repositories
## Severity
**LOW** (score: 2.0/10)

A default repository permission above read effectively grants every organization member write or admin access to all repositories, a broad, overly permissive access grant across the codebase.

## Summary
This check enforces that the GitHub organization's default repository base permission for all members is set to `read` (or left unset, which defaults conservatively), rather than a more permissive level like `write` or `admin`.

## Applicability
**Checkov framework(s):** `github_configuration`

Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated against the `default_repository_permission` field of the organization settings.

## Why it matters
The default base permission determines the access level every organization member automatically receives on every repository in the org, unless explicitly overridden. If this is set to `write` or `admin`, every member — including new hires, contractors, or bot accounts added to the org for unrelated purposes — automatically gets push/admin rights to every repository, including ones they have no legitimate business reason to touch. This dramatically expands the blast radius of a single compromised account: instead of being limited to the few repos that account was explicitly granted access to, the attacker can push malicious commits, alter workflows, or exfiltrate code from the organization's entire repository fleet. Defaulting to `read` follows least-privilege: elevated access should be granted explicitly per team/repository, not handed out organization-wide by default.

## How Checkov evaluates this
The check reads the organization's `default_repository_permission` setting. It passes when the value is `'read'` or `None` (unset, which the underlying `BaseOrganizationCheck` treats as an allowed default), and fails for any other value (e.g., `'write'`, `'admin'`, or `'none'` is not in the allowed list — note `'none'` failing here may be intentional metadata quirk, but the explicitly allowed values are only `read` and `None`).

## Non-compliant example
```json
{
  "default_repository_permission": "write"
}
```

## Remediated example
```json
{
  "default_repository_permission": "read"
}
```

## Remediation steps
1. In GitHub organization Settings > Member privileges > Base permissions, set the default repository permission to "Read".
2. If managed via Terraform, set `default_repository_permission = "read"` on the `github_organization_settings` resource.
3. Audit any teams/individuals that currently rely on the elevated default and grant them explicit `write`/`admin` access at the team or repository level instead.
4. Expect some initial friction from contributors who previously had implicit write access everywhere — communicate the change and the explicit-access request process before rolling it out.
5. Re-run the Checkov GitHub scan to confirm `default_repository_permission` now reports `read`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_strict_base_permissions_repository.py)
- [GitHub Docs: Setting base permissions for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/setting-base-permissions-for-an-organization)
