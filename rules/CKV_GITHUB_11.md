# CKV_GITHUB_11: Ensure GitHub branch protection dismisses stale review on new commit
## Severity
**MEDIUM** (score: 5.0/10)

Without dismissing stale approvals on new commits, a previously reviewed and approved PR can be silently amended with malicious changes that merge without a fresh security-relevant review.

## Summary
This check fails when a branch protection rule does not automatically dismiss existing pull-request approvals after new commits are pushed, checked via `required_pull_request_reviews/dismiss_stale_reviews`.

## Applicability
**Checkov framework(s):** `github_configuration`

- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings)
- **Entities:** `*`, evaluated against `required_pull_request_reviews/dismiss_stale_reviews`

## Why it matters
Code review is only a meaningful control if the code that was reviewed is the code that gets merged. Without "dismiss stale reviews," an approval granted on an earlier version of a PR remains valid even after the author (or anyone with push access to the PR branch) pushes additional commits — including commits made *after* the review, potentially introducing malicious or unreviewed changes. This is a known technique for slipping unreviewed code past a review gate: get an initial benign version approved, then push a follow-up commit that a reviewer never sees, and merge on the strength of the stale approval. Enabling `dismiss_stale_reviews` forces every new commit to invalidate prior approvals, guaranteeing a human reviews the actual final diff before merge.

## How Checkov evaluates this
This is a `BranchSecurity`-based check (`GithubBranchDismissStaleReviews`) evaluating `required_pull_request_reviews/dismiss_stale_reviews`. If `true`, the check **PASSES**; if `false` or absent, it **FAILS**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": false
  }
}
```
GitHub UI: **Settings → Branches → branch protection rule → "Dismiss stale pull request approvals when new commits are pushed"** left unchecked.

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  }
}
```

## Remediation steps
1. Go to **Settings → Branches**, edit the protection rule for the target branch.
2. Check **"Dismiss stale pull request approvals when new commits are pushed"**.
3. If using Terraform's `github_branch_protection` resource, set `required_pull_request_reviews.dismiss_stale_reviews = true`.
4. Pair this with required status checks (CKV_GITHUB_14) so that new commits both lose approval *and* must re-pass CI before merge.
5. Educate reviewers that they will need to re-approve after any post-review push — this is expected friction, not a bug.
6. Re-run Checkov to confirm the setting is enabled.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/dismiss_stale_reviews.py
- GitHub documentation on protected branches: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
