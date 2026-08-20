# CKV_GITHUB_10: Ensure branch protection rules are enforced on administrators
## Severity
**LOW** (score: 2.0/10)

Not enforcing branch protection rules on administrators lets any admin account (or one compromised via phished credentials) push directly to a protected branch, bypassing required reviews and status checks entirely.

## Summary
This check fails when a protected branch's `enforce_admins` setting is not enabled, meaning repository administrators can bypass the branch protection rules (required reviews, status checks, etc.) that everyone else must follow.

## Applicability
- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings pulled from the GitHub API)
- **Entities:** `*`, evaluated against the `enforce_admins/enabled` field of a branch protection rule

## Why it matters
Branch protection rules (required PR reviews, required status checks, restricted force-pushes, etc.) only provide real security value if they cannot be trivially bypassed. By default, GitHub exempts repository/organization administrators from branch protection rules unless "Include administrators" (`enforce_admins`) is explicitly turned on. This creates a significant gap: any account with admin rights on the repo — including an admin account that has been phished, has a stolen token, or is a rogue/compromised insider — can push directly to the protected branch, merge unreviewed code, or force-push over history, completely sidestepping code review and CI gates. Since admin accounts are exactly the accounts an attacker most wants to compromise (highest privilege, least friction), leaving this exemption in place undermines the entire purpose of branch protection.

## How Checkov evaluates this
This is a `BranchSecurity`-based check (`GithubBranchAdminEnforcement`) that evaluates the branch protection configuration key `enforce_admins/enabled`. If this boolean is `true` (administrators are included in / bound by the protection rule), the check **PASSES**; if `false` or absent, it **FAILS**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "enforce_admins": {
    "enabled": false
  }
}
```
GitHub UI: **Settings → Branches → Branch protection rule → "Do not allow bypassing the above settings"** (labelled "Include administrators" in older UI) left unchecked.

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "enforce_admins": {
    "enabled": true
  }
}
```

## Remediation steps
1. Go to **Settings → Branches** and edit the protection rule for the branch (e.g., `main`).
2. Check **"Do not allow bypassing the above settings"** (a.k.a. "Include administrators").
3. If managing branch protection via Terraform (`github_branch_protection` resource), set `enforce_admins = true`.
4. Communicate this change to admin users — they will now need to go through PRs like everyone else; establish a documented, audited break-glass process (e.g., a temporary, logged rule change) for genuine emergencies rather than relying on the standing exemption.
5. Re-run Checkov to confirm `enforce_admins.enabled` is `true`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/enforce_branch_protection_admins.py
- GitHub documentation on branch protection rules: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
