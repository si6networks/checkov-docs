# CKV_GIT_5: GitHub pull requests should require at least 2 approvals
## Severity
**MEDIUM** (score: 5.0/10)

Requiring fewer than 2 pull request approvals weakens the review control that guards against a single compromised or malicious contributor merging harmful code.

## Summary
This check ensures GitHub branch protection rules require at least two approving reviews before a pull request can be merged into a protected branch.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform configurations using the `github` provider, specifically the `github_branch_protection` and `github_branch_protection_v3` resources, at the `required_pull_request_reviews[0].required_approving_review_count` attribute.

## Why it matters
Branch protection review-count requirements are the primary control preventing a single individual — whether a legitimate but rushed/careless developer, or an attacker who has compromised one developer's account or token — from unilaterally merging changes into a protected branch (e.g., `main`/`production`). With only one (or zero) required approvals, a single compromised credential is sufficient to push a backdoor, disable a security control, or exfiltrate secrets through CI, with no independent second reviewer to catch it. Requiring at least two approvals enforces a real two-person integrity rule, raising the bar for both insider threats and credential-compromise scenarios, and is a widely recognized software-supply-chain best practice (e.g., SLSA's two-person review requirement).

## How Checkov evaluates this
`BranchProtectionReviewNumTwo` inspects `required_pull_request_reviews[0].required_approving_review_count`:
- If the `required_pull_request_reviews` block exists and `required_approving_review_count` is set to an integer value of `2` or greater, the check **PASSES**.
- In every other case — the block is missing, `required_approving_review_count` is unset, `0`, `1`, or non-numeric — the check **FAILS**.

## Non-compliant example
```hcl
resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"

  required_pull_request_reviews {
    required_approving_review_count = 1   # only one approval required
  }
}
```

## Remediated example
```hcl
resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"

  required_pull_request_reviews {
    required_approving_review_count = 2   # fix: require at least two approvals
    dismiss_stale_reviews            = true
  }
}
```

## Remediation steps
1. Set `required_approving_review_count = 2` (or higher) inside the `required_pull_request_reviews` block of every `github_branch_protection` / `github_branch_protection_v3` resource protecting a sensitive branch.
2. Also enable `dismiss_stale_reviews = true` so that new commits pushed after approval invalidate prior approvals, preventing a "approve-then-swap" bypass.
3. Combine with `require_code_owner_reviews = true` if you maintain a `CODEOWNERS` file, to ensure at least one required approver has domain expertise over the changed paths.
4. Confirm the branch protection pattern (`pattern = "main"`, or similar) actually matches your production/default branch naming — a typo here silently leaves the real branch unprotected.
5. Note this doubles as an operational change: enforcing 2 reviewers on a repo that previously required 0-1 may slow down merges until the team adapts its review workflow (e.g., staffing enough approvers, using auto-assign review rules).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/github/BranchProtectionReviewNumTwo.py)
- [Terraform GitHub provider: github_branch_protection](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection)
- [GitHub docs: About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
