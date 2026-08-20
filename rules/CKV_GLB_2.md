# CKV_GLB_2: Ensure GitLab branch protection rules does not allow force pushes
## Severity
**MEDIUM** (score: 5.0/10)

Allowing force pushes on protected GitLab branches lets an actor rewrite commit history to erase evidence of malicious changes or bypass required review state.

## Summary
This check ensures GitLab branch protection settings do not permit force pushes to protected branches.

## Applicability
Applies to Terraform configurations using the `gitlab` provider, specifically the `gitlab_branch_protection` resource, at the `allow_force_push` attribute.

## Why it matters
A force push (`git push --force`) rewrites a branch's commit history, discarding commits that other collaborators may already be building on. On a protected branch such as `main`, allowing force pushes creates serious risks: an attacker or a careless developer can silently overwrite/erase prior commits — destroying audit trail and code-review history, potentially removing evidence of a security incident, or reintroducing a previously-removed vulnerability/backdoor without it showing as a new, reviewable change. It also breaks other developers' local history and can bypass the intent of required-review controls, since a force push can replace already-reviewed commits with different (unreviewed) content while keeping the branch pointer superficially "the same." Disallowing force pushes on protected branches preserves an immutable, append-only history that underpins reliable code review and forensic auditability.

## How Checkov evaluates this
`ForcePushDisabled` is a `BaseResourceValueCheck` inspecting `allow_force_push`:
- **PASS** if the attribute is absent (`missing_block_result=PASSED` — the GitLab/provider default is to disallow force pushes).
- **PASS** if `allow_force_push` is explicitly `false`.
- **FAIL** if `allow_force_push` is explicitly `true`.

## Non-compliant example
```hcl
resource "gitlab_branch_protection" "main" {
  project            = gitlab_project.app.id
  branch             = "main"
  push_access_level  = "maintainer"
  merge_access_level = "maintainer"
  allow_force_push    = true   # force pushes permitted on protected branch
}
```

## Remediated example
```hcl
resource "gitlab_branch_protection" "main" {
  project            = gitlab_project.app.id
  branch             = "main"
  push_access_level  = "maintainer"
  merge_access_level = "maintainer"
  allow_force_push    = false  # fix: disallow force pushes to protected branch
}
```

## Remediation steps
1. Set `allow_force_push = false` (or simply omit the attribute, since it defaults to disallowed) on every `gitlab_branch_protection` resource for branches that need history integrity (main/release/production branches).
2. If a specific workflow genuinely requires force-push capability (e.g., a bot that rebases a long-lived feature branch), scope that need to a non-protected branch rather than weakening protection on `main`.
3. Combine with `code_owner_approval_required` and merge-request approval count settings (see `CKV_GLB_1`) for comprehensive branch protection.
4. Audit existing protected branches for `allow_force_push = true` and coordinate with the team before flipping it — if any legitimate workflow currently relies on force pushes to that branch, it will need to change first.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gitlab/ForcePushDisabled.py)
- [Terraform GitLab provider: gitlab_branch_protection](https://registry.terraform.io/providers/gitlabhq/gitlab/latest/docs/resources/branch_protection)
- [GitLab docs: Protected branches](https://docs.gitlab.com/ee/user/project/protected_branches.html)
