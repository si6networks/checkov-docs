# CKV_GITHUB_4: Ensure GitHub branch protection rules requires signed commits
## Severity
**LOW** (score: 2.0/10)

Unsigned commits let an attacker who gains push or history-rewrite access impersonate legitimate authors, undermining supply-chain provenance even though it doesn't itself grant access.

## Summary
This check enforces that a protected branch's branch protection rule requires all commits pushed to it to be cryptographically signed (e.g., GPG, SSH, or S/MIME signatures).

## Applicability
Applies to GitHub organization/repository configuration (`github_configuration` IaC type, entity `*`), evaluated against branch protection settings, specifically the `required_signatures.enabled` field.

## Why it matters
Without required commit signing, GitHub's commit author metadata (name and email) is trivially spoofable — anyone with write access, or anyone who has compromised a contributor's local git config or a CI credential, can author commits that appear to come from a different, more trusted identity. This undermines commit provenance/accountability, which is a foundational assumption for code review and incident forensics ("who actually wrote this change?"). Requiring signed commits ties each commit to a cryptographic key under the contributor's control, so a forged author identity can be detected, and a compromised push credential without the corresponding signing key cannot produce commits that GitHub will accept as verified — an important supply-chain integrity control, especially for release/production branches.

## How Checkov evaluates this
The check inspects `required_signatures.enabled` in the branch protection configuration (via the shared `BranchSecurity` base check). It passes when this is `True` and fails when it is `False` or missing.

## Non-compliant example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_signatures = false
}
```

## Remediated example
```hcl
resource "github_branch_protection" "main" {
  repository_id = "my-org/my-repo"
  pattern       = "main"

  required_signatures = true  # commits must be GPG/SSH signed
}
```

## Remediation steps
1. Open the branch protection rule for the protected branch (Settings > Branches, or the `github_branch_protection` Terraform resource).
2. Enable "Require signed commits".
3. Ensure all contributors to that branch have configured commit signing locally (`git config commit.gpgsign true` with a registered GPG key, or SSH signing keys registered with their GitHub account).
4. For automation/bots that commit to the branch, configure them to sign commits using a machine-managed signing key, or route their changes through pull requests merged by GitHub itself (which produces a verified merge commit).
5. Roll this out gradually — enabling it without contributor buy-in will block pushes from anyone without a configured signing key.
6. Re-run the Checkov GitHub scan to confirm `required_signatures.enabled` reports `true`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_signatures.py)
- [GitHub Docs: About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
