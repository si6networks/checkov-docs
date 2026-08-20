# CKV_GITHUB_12: Ensure GitHub branch protection restricts who can dismiss PR reviews
## Severity
**MEDIUM** (score: 6.0/10)

Leaving PR-review dismissal unrestricted lets any collaborator with dismissal rights clear a blocking security review and merge changes that were never actually approved.

## Summary
This check fails when a branch protection rule's `required_pull_request_reviews/dismissal_restrictions` setting is not configured to a specific, restricted set of users/teams — i.e., when review-dismissal rights are left unrestricted rather than limited to a defined, trusted group.

## Applicability
**Checkov framework(s):** `github_configuration`

- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings)
- **Entities:** `*`, evaluated against `required_pull_request_reviews/dismissal_restrictions`

## Why it matters
By default, anyone with write access to a repository can dismiss an existing PR review's approval or rejection status. This means a control meant to require independent human sign-off — required PR reviews — can be undermined by any collaborator simply dismissing a rejecting review (or a colleague's approval they don't like) and then merging, without the dismissal itself being restricted to a small, accountable set of people. Restricting dismissal rights to specific users or teams (e.g., senior maintainers or a security team) ensures that overriding a review decision is a deliberate, limited-authority action rather than something any contributor can do unilaterally, preserving the integrity of the review-gate control.

## How Checkov evaluates this
This check (`GithubBranchDismissalRestrictions`) is implemented via `NegativeBranchSecurity`, evaluating the key `required_pull_request_reviews/dismissal_restrictions` against a list of forbidden values containing Checkov's `ANY_VALUE` sentinel. In practice this means the check is looking for the `dismissal_restrictions` field to hold a specific, defined configuration (an explicit `users`/`teams` restriction) rather than being left at its unrestricted default. If the field is missing or not meaningfully restricted, the check **FAILS**; if dismissal rights are scoped to specific users/teams, it **PASSES**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  }
}
```
No `dismissal_restrictions` configured — any collaborator with write access can dismiss reviews. (This feature also requires a paid GitHub plan on organization repositories.)

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "dismissal_restrictions": {
      "users": ["release-manager"],
      "teams": ["maintainers"]
    }
  }
}
```

## Remediation steps
1. Go to **Settings → Branches**, edit the branch protection rule, and enable **"Restrict who can dismiss pull request reviews"**.
2. Add only the specific users or teams who should have this authority (e.g., release managers, security leads) — avoid adding broad groups.
3. Note this feature is only available on GitHub Team/Enterprise plans for organization-owned repositories.
4. If using Terraform, set `required_pull_request_reviews.dismissal_restrictions` (or the equivalent `restrict_dismissals`/`dismissal_restrictions_users`/`dismissal_restrictions_teams` arguments, depending on provider version) to the intended users/teams.
5. Periodically audit the restricted list to ensure it stays minimal as team membership changes.
6. Re-run Checkov to confirm dismissal rights are explicitly restricted.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/restrict_pr_review_dismissal.py
- GitHub documentation on branch protection settings: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
