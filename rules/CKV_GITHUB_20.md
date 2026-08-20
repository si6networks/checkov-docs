# CKV_GITHUB_20: Ensure open git branches are up to date before they can be merged into codebase
## Severity
**LOW** (score: 2.0/10)

Merging a branch that isn't up to date with the target can silently reintroduce vulnerabilities fixed upstream or bypass status checks that ran against stale code, but exploitation requires a specific race condition rather than a direct attack path.

## Summary
This check enforces that a repository's branch protection rule requires branches to be up-to-date with the base branch (strict status checks) before they can be merged.

## Applicability
Applies to GitHub organization/repository configuration (`github_configuration` IaC type, entity `*`), evaluated against branch protection settings (e.g., the `github_branch_protection` Terraform resource or equivalent exported GitHub API configuration).

## Why it matters
Without the "strict" status checks setting, a pull request can pass its CI checks against an old, stale copy of the base branch and then be merged even though the base branch has since changed in ways that could break the combined result — a classic "semantic merge conflict" that automated tests never actually validated. This is more than a reliability nit: it can silently reintroduce vulnerabilities that were already fixed on the base branch, merge code that conflicts with a since-merged security patch, or ship a change whose CI-verified security scan results no longer reflect what's actually being deployed. Requiring branches to be up to date before merge (i.e., re-running status checks after each new push to the base) ensures the tested state and the merged state are the same.

## How Checkov evaluates this
The check inspects `required_status_checks.strict` in the branch protection configuration. It fails when that value is `False` (or missing, since the check is configured with `missing_attribute_result=CheckResult.FAILED`). It passes only when `strict` is explicitly `True`, meaning GitHub will require the branch to be up to date with the base branch before allowing a merge.

## Non-compliant example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_status_checks {
    strict   = false
    contexts = ["ci/build"]
  }
}
```

## Remediated example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_status_checks {
    strict   = true   # branch must be up to date with base before merge
    contexts = ["ci/build"]
  }
}
```

## Remediation steps
1. Open the repository's branch protection rule for the protected branch (Settings > Branches, or the `github_branch_protection` resource).
2. Under "Require status checks to pass before merging", enable "Require branches to be up to date before merging" (this maps to `required_status_checks.strict = true`).
3. Ensure at least one required status check context is configured, otherwise the strict setting has limited effect.
4. Be aware this can slow down merges in high-traffic repositories, since contributors will need to rebase/update their branch and re-run CI whenever the base branch moves — consider combining with a merge queue to reduce friction.
5. Re-scan with Checkov to confirm `required_status_checks.strict` now reports `true`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_updated_branch_pr.py)
- [GitHub Docs: About protected branches — require branches to be up to date before merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
