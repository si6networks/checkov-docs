# CKV_GITHUB_18: Ensure GitHub branch protection rules does not allow deletions
## Severity
**MEDIUM** (score: 5.0/10)

Allowing deletion of a protected branch creates an availability/integrity risk (loss of history, disruption of release or audit trails) rather than a direct confidentiality or code-execution exposure.

## Summary
This check fails when a branch protection rule permits the protected branch to be deleted (`allow_deletions/enabled` is `true`), rather than requiring it to be `false`.

## Applicability
**Checkov framework(s):** `github_configuration`

- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings)
- **Entities:** `*`, evaluated against `allow_deletions/enabled`, with an expected value of `false`

## Why it matters
A protected branch — typically `main`/`master` or a release branch — is the canonical, trusted history of the project, often serving as the source of truth for deployments, audits, and compliance evidence. If branch deletion is allowed, anyone with sufficient permissions (or an attacker using a compromised token) can delete the branch outright, which:
- Destroys the record of what was actually reviewed, tested, and deployed, undermining any audit trail or incident investigation that depends on git history.
- Can be used as a denial-of-service or sabotage action against active development — restoring from a deleted branch requires someone to recreate it from a local clone or another remote, causing outages and lost work if not everyone has an up-to-date copy.
- Combined with force-push allowances, could be part of a broader attack to erase evidence of a malicious commit after the fact.

Disabling branch deletion for protected branches ensures this destructive action isn't available even to accounts with elevated repository permissions, absent an explicit, deliberate unprotection step.

## How Checkov evaluates this
This is a `BranchSecurity`-based check (`GithubBranchDisallowDeletions`) that evaluates `allow_deletions/enabled` against an explicit expected value of `False` (overriding the base class's default expectation). If `allow_deletions.enabled` is `false` (deletions are not allowed), the check **PASSES**; if `true`, it **FAILS**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "allow_deletions": {
    "enabled": true
  }
}
```

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "allow_deletions": {
    "enabled": false
  }
}
```

## Remediation steps
1. Go to **Settings → Branches**, edit the branch protection rule, and ensure **"Allow deletions"** is left **unchecked** (this is the default, secure state).
2. If using Terraform's `github_branch_protection` resource, ensure `allow_deletions = false` (or omit the attribute, since `false` is the provider default).
3. If a branch genuinely needs to be retired, do so through a deliberate, reviewed process (e.g., temporarily loosening the protection rule with a documented change) rather than leaving deletion permanently allowed.
4. Combine with disallowing force pushes on the same branch protection rule for full history-integrity protection.
5. Re-run Checkov to confirm `allow_deletions.enabled` is `false`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/disallow_branch_deletions.py
- GitHub documentation on protected branches: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
