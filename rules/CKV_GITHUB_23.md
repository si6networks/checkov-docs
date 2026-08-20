# CKV_GITHUB_23: Ensure internal repository creation is limited to specific members
## Severity
**LOW** (score: 2.0/10)

Unrestricted internal repository creation broadens who can see and copy company-wide code, but the exposure stays inside the org boundary rather than reaching the public internet.

## Summary
This check enforces that a GitHub Enterprise organization does not allow all members to freely create new internal (enterprise-wide visible) repositories.

## Applicability
**Checkov framework(s):** `github_configuration`

Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated against the organization-level settings document (`members_can_create_internal_repositories`). This setting is specific to GitHub Enterprise, where "internal" is a visibility level between private and public, visible to all enterprise members across the org's parent enterprise account.

## Why it matters
Internal repositories are visible to every member of the entire enterprise account, not just the immediate team or organization that created them — effectively a much larger blast radius than a normal private repository. If any member can create internal repos at will, sensitive code, credentials, or business logic intended for a small team can become readable by potentially thousands of employees across unrelated business units, without the originating team realizing how broad the exposure is. Restricting internal repo creation to specific trusted members ensures this wide-visibility option is used deliberately, with an understanding of its scope, rather than by default.

## How Checkov evaluates this
The check reads `members_can_create_internal_repositories` from the organization configuration. It passes only when the value is explicitly `False`. Any other value, including `True` or a missing attribute (`missing_attribute_result=CheckResult.FAILED`), fails.

## Non-compliant example
```json
{
  "members_can_create_internal_repositories": true
}
```

## Remediated example
```json
{
  "members_can_create_internal_repositories": false
}
```

## Remediation steps
1. In your GitHub Enterprise organization Settings > Member privileges > Repository creation, disable the option allowing members to create internal repositories.
2. If managed via Terraform, set `members_can_create_internal_repositories = false` on the `github_organization_settings` resource and apply.
3. Define a small set of trusted roles/teams (e.g., platform engineering) who retain the ability to create internal repos when it is genuinely the right visibility choice.
4. Educate teams on the difference between private and internal visibility, since the wrong choice is often accidental rather than malicious.
5. Re-run the Checkov GitHub scan to confirm the setting reports `false`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/internal_repository_creation_is_limited.py)
- [GitHub Docs: Restricting repository creation in your organization](https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization)
