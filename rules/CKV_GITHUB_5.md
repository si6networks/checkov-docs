# CKV_GITHUB_5: Ensure GitHub branch protection rules does not allow force pushes
## Severity
**MEDIUM** (score: 5.5/10)

Allowing force pushes on protected branches lets history (and any record of a malicious or erroneous commit) be rewritten or hidden, weakening the integrity of the audit trail.

## Summary
This check enforces that a protected branch's branch protection rule disallows force pushes, preventing contributors (and their tools) from overwriting the branch's commit history.

## Applicability
**Checkov framework(s):** `github_configuration`

Applies to GitHub organization/repository configuration (`github_configuration` IaC type, entity `*`), evaluated against branch protection settings, specifically `allow_force_pushes.enabled`.

## Why it matters
A force push rewrites a branch's history rather than appending to it, which can silently delete previously reviewed and merged commits — including security fixes, audit trail entries, and prior approved review context — and replace them with different content under the same branch name. This is a significant integrity and forensic risk: an attacker with push access (or a compromised CI credential) could force-push to erase evidence of a malicious commit, or overwrite a fix that was already deployed based on that branch's prior state, causing environments to silently diverge from what was reviewed. It also breaks the guarantee that a commit SHA once seen on a protected branch stays there, which many downstream systems (deployment pipelines, artifact provenance, compliance audits) implicitly rely on.

## How Checkov evaluates this
The check inspects `allow_force_pushes.enabled` in the branch protection configuration. The expected/passing value is `False` — force pushes must be disallowed. If `allow_force_pushes.enabled` is `True` (or the setting otherwise doesn't resolve to `False`), the check fails.

## Non-compliant example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  allows_force_pushes = true
}
```

## Remediated example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  allows_force_pushes = false  # history rewrites are blocked
}
```

## Remediation steps
1. Open the branch protection rule for the protected branch (Settings > Branches, or the `github_branch_protection` Terraform resource).
2. Ensure "Allow force pushes" is disabled (unchecked) — it should be off by default, but confirm explicitly.
3. If specific automation genuinely needs to force-push (e.g., a bot that rewrites a release branch), scope the exception narrowly to a specific team/actor rather than allowing it organization- or repository-wide.
4. Educate contributors to use `git revert` or new commits instead of `git push --force` for correcting mistakes on shared/protected branches.
5. Re-run the Checkov GitHub scan to confirm `allow_force_pushes.enabled` reports `false`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/disallow_force_pushes.py)
- [GitHub Docs: About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
