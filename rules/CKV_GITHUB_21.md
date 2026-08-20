# CKV_GITHUB_21: Ensure public repository creation is limited to specific members
## Severity
**LOW** (score: 2.0/10)

Unrestricted ability to create public repositories creates a real risk that proprietary code, credentials, or internal data are accidentally exposed to the internet.

## Summary
This check enforces that a GitHub organization does not allow all members to create new public repositories.

## Applicability
Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated against the organization-level settings document (e.g., `members_can_create_public_repositories` in the org configuration).

## Why it matters
Allowing any organization member to freely create public repositories creates a significant, hard-to-monitor data-exposure and reputational risk. Any member — including a compromised account, a disgruntled employee, or someone acting carelessly — can instantly publish internal code, credentials accidentally committed to a repo, proprietary business logic, or unreleased product details to the public internet, often without any review process. Once public, content can be cloned, indexed, and cached by third parties within minutes, making the leak effectively irreversible even if the repository is later made private or deleted. Restricting public repo creation to specific trusted members/admins adds a deliberate gate before anything leaves the organization's controlled boundary.

## How Checkov evaluates this
The check reads the `members_can_create_public_repositories` field from the organization configuration. It passes only when the value is explicitly `False`. Any other value — including `True` or the attribute being entirely absent (`missing_attribute_result=CheckResult.FAILED`) — causes a failure.

## Non-compliant example
```json
{
  "members_can_create_public_repositories": true
}
```

## Remediated example
```json
{
  "members_can_create_public_repositories": false
}
```

## Remediation steps
1. Go to your GitHub organization Settings > Member privileges (or "Repository creation" section).
2. Under "Repository creation", uncheck/disable the option allowing members to create public repositories.
3. If some individuals still need this ability, grant it via a dedicated team with elevated permissions or through an approval workflow, rather than org-wide.
4. If managed via Terraform, set the corresponding `github_organization_settings` argument (`members_can_create_public_repositories = false`) and apply.
5. Communicate the change to engineering teams, since legitimate open-source publishing workflows may need a documented exception process (e.g., a designated open-source release team).
6. Re-run the Checkov GitHub scan to confirm the setting now reports `false`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/public_repository_creation_is_limited.py)
- [GitHub Docs: Restricting repository creation in your organization](https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization)
