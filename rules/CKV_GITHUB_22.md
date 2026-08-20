# CKV_GITHUB_22: Ensure private repository creation is limited to specific members
## Severity
**LOW** (score: 2.0/10)

Unrestricted private repository creation mainly drives governance sprawl and inconsistent access review rather than a direct external exposure path.

## Summary
This check enforces that a GitHub organization does not allow all members to freely create new private repositories.

## Applicability
Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated against the organization-level settings document (`members_can_create_private_repositories`).

## Why it matters
Unrestricted private repository creation leads to sprawl of unmanaged, unmonitored repositories that fall outside the organization's security baseline — they may lack required branch protection, secret scanning, dependency review, or CODEOWNERS enforcement that is otherwise applied through templates or org-wide policy. This sprawl makes it far easier for sensitive data (customer data, credentials, internal IP) to land in a repository nobody is actively securing or auditing, and complicates incident response and inventory/asset management (you can't secure what you don't know exists). Limiting who can create private repositories keeps the organization's repository inventory intentional and governable.

## How Checkov evaluates this
The check reads `members_can_create_private_repositories` from the organization configuration. It passes only when the value is explicitly `False`. Any other value, including `True` or a missing attribute (`missing_attribute_result=CheckResult.FAILED`), fails.

## Non-compliant example
```json
{
  "members_can_create_private_repositories": true
}
```

## Remediated example
```json
{
  "members_can_create_private_repositories": false
}
```

## Remediation steps
1. In your GitHub organization Settings > Member privileges > Repository creation, disable the option allowing members to create private repositories.
2. If using Terraform, set `members_can_create_private_repositories = false` on the `github_organization_settings` resource and apply.
3. Establish a controlled process (a dedicated team, request form, or platform-engineering-owned repo creation pipeline) for legitimate new repository needs, so this restriction doesn't become a bottleneck.
4. Apply organization repository templates/rulesets to any centrally-created repositories so new repos inherit required security controls automatically.
5. Re-run the Checkov GitHub scan to confirm the setting reports `false`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/private_repository_creation_is_limited.py)
- [GitHub Docs: Restricting repository creation in your organization](https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization)
