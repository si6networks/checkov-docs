# CKV_GITLAB_1: Merge requests should require at least 2 approvals
## Severity
**MEDIUM** (score: 5.0/10)

Allowing fewer than 2 required MR approvals weakens the code-review control that protects against a single compromised or malicious account merging unreviewed, potentially harmful changes.

## Summary
This check ensures that a GitLab project's merge-request approval configuration requires at least two approvals before a merge request can be merged.

## Applicability
**Checkov framework(s):** `gitlab_configuration`

Applies to GitLab project-level configuration scanned by Checkov's `gitlab_configuration` framework (Checkov reads exported GitLab project/approval settings, e.g. via the GitLab API/settings JSON, rather than a Terraform resource). It targets the project approvals settings document (matched against the `project_approvals` schema), applicable to any GitLab project (`"*"` entity).

## Why it matters
Merge request (MR) approval gating is a core code-review control. If only a single approver — or no approver — is required, a single compromised account, a rushed self-approval, or a socially-engineered reviewer can merge malicious or vulnerable code (backdoors, disabled security checks, dependency confusion, CI/CD pipeline tampering) directly into protected branches with no independent second check. Requiring at least two approvals enforces separation of duties: it makes it materially harder for one compromised or malicious insider to single-handedly introduce changes, and it improves the odds that a reviewer catches a defect the first reviewer missed. This is a standard supply-chain / SDLC integrity control (comparable to GitHub's "require pull request reviews" branch protection).

## How Checkov evaluates this
The check (`MergeRequestRequiresApproval`) first validates the scanned configuration document against the `project_approvals` schema — if the document doesn't match that schema (i.e., it isn't a project-approvals settings object), the check returns `None` (not applicable/skipped). If it does match, Checkov reads the `approvals_before_merge` field:
- If `approvals_before_merge` is less than 2 (including missing/defaulting to 0), the check **FAILS**.
- If `approvals_before_merge` is 2 or greater, the check **PASSES**.

## Non-compliant example
A GitLab project approvals configuration (as read/exported by Checkov) with fewer than 2 required approvals:

```json
{
  "approvals_before_merge": 1,
  "reset_approvals_on_push": true,
  "disable_overriding_approvers_per_merge_request": false
}
```

## Remediated example
```json
{
  "approvals_before_merge": 2,
  "reset_approvals_on_push": true,
  "disable_overriding_approvers_per_merge_request": true
}
```

## Remediation steps
1. In GitLab, navigate to **Settings > Merge requests > Merge request approvals** for the project (or set it via the Projects API `approvals_before_merge` field, or via a `gitlab_project` / GitLab project-approval-rule Terraform resource if you manage GitLab as code).
2. Set **Approvals required** (`approvals_before_merge`) to `2` or higher.
3. Also consider enabling `reset_approvals_on_push` so approvals don't carry over to new, un-reviewed commits, and `disable_overriding_approvers_per_merge_request` so authors can't lower the required count per-MR.
4. If enforced organization-wide, configure this via a group-level approval rule or a compliance framework in GitLab Premium/Ultimate so individual projects can't opt out.
5. Note: this check inspects settings/config that Checkov has exported/scanned as a `gitlab_configuration` document — ensure your Checkov scan target actually includes this settings data source for the check to run at all.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/gitlab/checks/merge_requests_approvals.py)
- [GitLab docs: Merge request approval rules](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
