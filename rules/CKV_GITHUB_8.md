# CKV_GITHUB_8: Ensure GitHub branch protection rules requires linear history
## Severity
**LOW** (score: 3.0/10)

Requiring linear history is primarily an operational/audit-clarity practice and does not by itself close an exploitable attack path.

## Summary
This check enforces that a protected branch's branch protection rule requires a linear commit history, blocking merge commits in favor of rebase or squash merges.

## Applicability
Applies to GitHub organization/repository configuration (`github_configuration` IaC type, entity `*`), evaluated against branch protection settings, specifically `required_linear_history.enabled`.

## Why it matters
While primarily a code-quality/maintainability control, linear history has meaningful security and auditability benefits: a clean, linear commit sequence makes it far easier to accurately `git bisect` a regression or vulnerability back to the exact commit that introduced it, and to reason about "what code was actually running at time T" for incident response. Non-linear history with merge commits can obscure the true order of changes and make automated tooling (SCA scanners, provenance/attestation systems, bisection scripts) less reliable at pinpointing when a vulnerable dependency or insecure code pattern was introduced, which slows down root-cause analysis during a security incident.

## How Checkov evaluates this
The check inspects `required_linear_history.enabled` in the branch protection configuration (via the shared `BranchSecurity` base check). It passes when this is `True` and fails when it is `False` or missing (the base check applies a `PASSED`/expected-value comparison similar to related `BranchSecurity` checks).

## Non-compliant example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_linear_history = false
}
```

## Remediated example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_linear_history = true  # merge commits are blocked; rebase/squash only
}
```

## Remediation steps
1. Open the branch protection rule for the protected branch (Settings > Branches, or the `github_branch_protection` Terraform resource).
2. Enable "Require linear history".
3. Configure the repository's merge button settings to allow only "Squash merging" and/or "Rebase merging", disabling "Create a merge commit", so contributors aren't blocked by a mismatch between allowed merge strategies and this branch protection rule.
4. Communicate the workflow change to contributors who are used to merge commits, since existing local branches with merge commits will need to be rebased before they can merge.
5. Re-run the Checkov GitHub scan to confirm `required_linear_history.enabled` reports `true`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_linear_history.py)
- [GitHub Docs: About protected branches — require linear history](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
