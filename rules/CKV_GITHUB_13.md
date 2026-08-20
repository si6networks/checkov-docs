# CKV_GITHUB_13: Ensure GitHub branch protection requires CODEOWNER reviews
## Severity
**MEDIUM** (score: 5.0/10)

Without required CODEOWNER review, changes to sensitive paths (CI config, infra code, security-critical modules) can be merged without sign-off from the people accountable for that code's security posture.

## Summary
This check fails when a branch protection rule does not require review from designated code owners (`required_pull_request_reviews/require_code_owner_reviews`), meaning changes to sensitive files/paths can be merged without sign-off from the people responsible for them.

## Applicability
**Checkov framework(s):** `github_configuration`

- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings)
- **Entities:** `*`, evaluated against `required_pull_request_reviews/require_code_owner_reviews`

## Why it matters
A `CODEOWNERS` file lets a repository designate specific individuals or teams as owners of particular directories or file patterns (e.g., `/infra/` owned by the platform team, `/auth/` owned by the security team). Without enforcing code-owner review, this ownership mapping is purely informational — anyone whose approval satisfies the generic "required reviewers" count can approve a PR touching security-critical code (authentication logic, IAM policies, CI/CD workflows, secrets handling) even if no one with actual domain expertise or authority over that area ever looked at it. This creates a gap where sensitive subsystems can be modified by reviewers unfamiliar with their security implications, increasing the chance that a subtly dangerous change (e.g., a loosened permission check, a backdoored dependency pin) is approved without proper scrutiny.

## How Checkov evaluates this
This is a `BranchSecurity`-based check (`GithubBranchRequireCodeOwnerReviews`) evaluating `required_pull_request_reviews/require_code_owner_reviews`. If `true`, the check **PASSES**; if `false` or absent, it **FAILS**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": false
  }
}
```

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true
  }
}
```

## Remediation steps
1. Create (or verify) a `CODEOWNERS` file at the repository root, `.github/`, or `docs/`, mapping critical paths (e.g., `/.github/workflows/`, `/infra/`, `/auth/`) to specific users or teams.
2. Go to **Settings → Branches**, edit the branch protection rule, and check **"Require review from Code Owners"**.
3. If using Terraform's `github_branch_protection` resource, set `required_pull_request_reviews.require_code_owner_reviews = true`.
4. Ensure the code owners listed in `CODEOWNERS` are actual, current team members with the necessary repo access — a stale or empty CODEOWNERS entry can silently block merges or fail to enforce the intended ownership.
5. Combine with required status checks and stale-review dismissal (CKV_GITHUB_14, CKV_GITHUB_11) for a complete review-integrity control set.
6. Re-run Checkov to confirm `require_code_owner_reviews` is `true`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_code_owner_reviews.py
- GitHub documentation on CODEOWNERS: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners
