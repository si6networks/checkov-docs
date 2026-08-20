# CKV_GITHUB_19: Ensure any change to code receives approval of two strongly authenticated users
## Severity
**HIGH** (score: 7.5/10)

Allowing a single reviewer (or no review) to approve merges removes a key control against a compromised or malicious insider account pushing unreviewed code into the default branch.

## Summary
This check enforces that a GitHub repository's branch protection rule requires at least two approving pull request reviews before a change can be merged.

## Applicability
Applies to GitHub organization/repository configuration (`github_configuration` IaC type), evaluated against branch protection settings exported from the GitHub API/Terraform `github_branch_protection` style configuration collected by Checkov's GitHub provider integration. Entity type is `*` (the branch protection document as a whole).

## Why it matters
Pull request review requirements are one of the primary controls preventing a single compromised or malicious account from pushing unreviewed code into a protected branch (e.g., `main`). A single-approver requirement is vulnerable to social engineering, insider threats, or an attacker who has compromised one legitimate contributor's account/credentials — that one compromised identity is sufficient to get arbitrary code merged and shipped. Requiring two independent approvals adds a second, unrelated line of human review, which meaningfully raises the bar for supply-chain attacks that rely on sneaking a malicious commit past code review (a well-documented technique in real-world CI/CD compromises).

## How Checkov evaluates this
The check reads the branch protection configuration's `required_pull_request_reviews.required_approving_review_count` field. It fails when that value is `None` (branch protection reviews not configured at all), `0`, or `1` — i.e., anything less than 2 approvals. Any value of 2 or greater passes. If the attribute is entirely missing from the configuration, the check is explicitly configured with `missing_attribute_result=CheckResult.FAILED`, so an absent setting is treated as a failure rather than being skipped.

## Non-compliant example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_pull_request_reviews {
    required_approving_review_count = 1
  }
}
```

## Remediated example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_pull_request_reviews {
    required_approving_review_count = 2  # requires two independent approvals
  }
}
```

## Remediation steps
1. Open the repository's branch protection rule (Settings > Branches, or the `github_branch_protection` Terraform resource / GitHub API/App configuration Checkov is scanning).
2. Enable "Require a pull request before merging" if not already enabled.
3. Set "Require approvals" and configure the required number of approving reviews to `2` (or higher for especially sensitive branches).
4. Consider pairing this with `Require review from Code Owners` and dismissal of stale approvals on new commits, for stronger enforcement.
5. Ensure the branch protection rule applies to the actual default/production branch pattern (`main`, `master`, or your release branch naming convention) — a rule scoped to the wrong pattern will not protect the intended branch.
6. If reviews are managed purely through the GitHub UI/API rather than Terraform, verify the same setting via the GitHub organization/repository settings so Checkov's GitHub configuration scan reflects the corrected value.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_2approvals.py)
- [GitHub Docs: About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
