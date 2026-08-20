# CKV_GLB_1: Ensure at least two approving reviews are required to merge a GitLab MR
## Severity
**MEDIUM** (score: 5.0/10)

Allowing fewer than 2 required MR approvals weakens the code-review control that protects against a single compromised or malicious account merging unreviewed, potentially harmful changes.

## Summary
This check ensures a GitLab project's Terraform-managed configuration requires at least two approving reviews before a merge request can be merged.

## Applicability
Applies to Terraform configurations using the `gitlab` provider, specifically the `gitlab_project` resource, at the `approvals_before_merge` attribute.

## Why it matters
Merge request approval count is the primary control against a single compromised account or a rushed/careless single reviewer merging harmful changes into a project (backdoors, disabled security scans, malicious dependency bumps, CI/CD pipeline tampering). With `approvals_before_merge` set to 0 or 1, one person — legitimately or via a stolen credential/token — can single-handedly approve and merge changes with no independent second check. Requiring at least two approvals establishes real separation of duties and is a standard software-supply-chain integrity control.

## How Checkov evaluates this
`RequireTwoApprovalsToMerge` inspects the `approvals_before_merge` attribute of the `gitlab_project` resource:
- The value is coerced to an integer (`force_int`).
- **PASS** if the resulting integer is `2` or greater.
- **FAIL** in all other cases — the attribute is missing, non-numeric, `0`, or `1`.

## Non-compliant example
```hcl
resource "gitlab_project" "app" {
  name                   = "payments-service"
  visibility_level       = "private"
  approvals_before_merge = 1   # only one approval required
}
```

## Remediated example
```hcl
resource "gitlab_project" "app" {
  name                   = "payments-service"
  visibility_level       = "private"
  approvals_before_merge = 2   # fix: require at least two approvals before merge
}
```

## Remediation steps
1. Set `approvals_before_merge = 2` (or higher) on every `gitlab_project` resource, or configure it via the equivalent `gitlab_project_approval_rule` resource for finer-grained rule control (specific approvers/groups).
2. For GitLab Premium/Ultimate, consider defining a `gitlab_project_approval_rule` with named required approver groups (e.g., security team) rather than a bare count, for stronger assurance than "any 2 people."
3. Enable "Prevent approval by author" and "Remove all approvals when new commits are added" alongside this setting so the two-approval guarantee can't be trivially bypassed by self-approval or by pushing new code after approval.
4. Roll out gradually if the project currently has few active reviewers — raising the approval bar can create merge bottlenecks until enough reviewers are onboarded.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gitlab/RequireTwoApprovalsToMerge.py)
- [Terraform GitLab provider: gitlab_project](https://registry.terraform.io/providers/gitlabhq/gitlab/latest/docs/resources/project)
- [GitLab docs: Merge request approval rules](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
