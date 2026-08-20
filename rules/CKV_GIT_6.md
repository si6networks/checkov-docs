# CKV_GIT_6: Ensure GitHub branch protection rules requires signed commits
## Severity
**LOW** (score: 2.0/10)

Not requiring signed commits on protected branches makes it impossible to cryptographically verify commit authorship, weakening supply-chain provenance without itself enabling a direct exploit.

## Summary
This check ensures GitHub branch protection rules require that all commits pushed to a protected branch be cryptographically signed.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform configurations using the `github` provider, specifically the `github_branch_protection` and `github_branch_protection_v3` resources, at the `require_signed_commits` attribute.

## Why it matters
Git commit authorship (the `author`/`committer` name and email) is trivially spoofable — anyone can `git config user.email "someone-else@company.com"` and produce a commit that appears to come from another person. Without required commit signing (GPG, S/MIME, or SSH signatures), there is no cryptographic guarantee that a commit actually originated from the claimed author, making it easier for an attacker with repository write access (e.g., via a compromised CI token or a merged malicious PR from a look-alike account) to impersonate a trusted maintainer in the commit history — undermining audit trails, incident forensics, and any process that relies on "who actually wrote this code." Requiring signed commits (and GitHub's verification of the signature against a known key) closes this gap by cryptographically binding each commit to a specific, verifiable identity.

## How Checkov evaluates this
`BranchProtectionRequireSignedCommits` is a `BaseResourceValueCheck` inspecting `require_signed_commits`:
- **PASS** only if `require_signed_commits` is explicitly `true`.
- **FAIL** if the attribute is `false`, or if it is entirely absent (`missing_block_result=FAILED` — i.e., unlike some other checks in this provider, omission is treated as insecure-by-default here, since GitHub's own default is not to require signed commits).

## Non-compliant example
```hcl
resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"

  required_pull_request_reviews {
    required_approving_review_count = 2
  }
  # require_signed_commits not set -> defaults to unsigned commits allowed
}
```

## Remediated example
```hcl
resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"

  required_pull_request_reviews {
    required_approving_review_count = 2
  }

  require_signed_commits = true   # fix: enforce commit signature verification
}
```

## Remediation steps
1. Add `require_signed_commits = true` to every `github_branch_protection` / `github_branch_protection_v3` resource protecting sensitive branches.
2. Ensure developers have GPG, SSH, or S/MIME signing keys configured locally and registered with their GitHub account (`git config commit.gpgsign true` plus a registered key), and that CI/bot accounts pushing to protected branches also sign their commits or are routed through a properly-signed merge process.
3. Roll this out with communication/tooling support — enabling this on a repo where developers haven't set up signing will immediately block all pushes to the protected branch until they configure signing keys.
4. Consider requiring signed *and* verified* commits specifically (GitHub distinguishes "signed" from "verified" — a signature must chain to a key GitHub recognizes as belonging to the committer) as part of your key management process.
5. Combine with required PR reviews (`CKV_GIT_5`) for defense in depth: signing verifies identity, reviews verify content.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/github/BranchProtectionRequireSignedCommits.py)
- [Terraform GitHub provider: github_branch_protection](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection)
- [GitHub docs: About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
