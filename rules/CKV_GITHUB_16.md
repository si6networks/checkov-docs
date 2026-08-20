# CKV_GITHUB_16: Ensure GitHub branch protection requires conversation resolution
## Severity
**MEDIUM** (score: 4.5/10)

Not requiring conversation resolution before merge allows unresolved reviewer concerns, including flagged security issues, to be merged without ever being addressed.

## Summary
This check fails when a branch protection rule does not require all pull-request review conversations to be resolved before merging (`required_conversation_resolution/enabled`).

## Applicability
**Checkov framework(s):** `github_configuration`

- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings)
- **Entities:** `*`, evaluated against `required_conversation_resolution/enabled`

## Why it matters
Reviewers frequently leave inline comments raising concerns — a possible bug, a security question about input validation, a request to add a missing check — without necessarily blocking the PR with a formal "Request changes" review, especially in fast-moving teams. Without requiring conversation resolution, these open review threads can be silently ignored: the PR can be merged while unresolved questions or flagged issues sit unaddressed, effectively letting real feedback (including security-relevant feedback) fall through the cracks. Requiring all conversations to be marked resolved before merge forces an explicit, auditable decision on every raised concern — either it's fixed, or someone consciously resolves the thread as not applicable — rather than allowing it to be merged around unnoticed.

## How Checkov evaluates this
This is a `BranchSecurity`-based check (`GithubBranchRequireConversationResolution`) evaluating `required_conversation_resolution/enabled`. If `true`, the check **PASSES**; if `false` or absent, it **FAILS**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "required_conversation_resolution": {
    "enabled": false
  }
}
```

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "required_conversation_resolution": {
    "enabled": true
  }
}
```

## Remediation steps
1. Go to **Settings → Branches**, edit the branch protection rule, and check **"Require conversation resolution before merging"**.
2. If using Terraform's `github_branch_protection` resource, set `required_conversation_resolution = true`.
3. Establish a team norm that "resolving" a thread means the concern was actually addressed (in code or in a follow-up discussion), not just dismissed to unblock the merge button.
4. Combine with required reviews and status checks (CKV_GITHUB_13, CKV_GITHUB_14) for comprehensive review-gate coverage.
5. Re-run Checkov to confirm `required_conversation_resolution.enabled` is `true`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_conversation_resolution.py
- GitHub documentation on protected branches: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
