# CKV_GLB_4: Ensure GitLab commits are signed
## Severity
**LOW** (score: 2.0/10)

Not rejecting unsigned commits makes it impossible to cryptographically verify commit authorship, weakening supply-chain provenance without itself enabling a direct exploit.

## Summary
This check ensures a GitLab project's push rules reject any commit that is not cryptographically signed.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform configurations using the `gitlab` provider, specifically the `gitlab_project` resource, at the `push_rules[0].reject_unsigned_commits` attribute.

## Why it matters
Like GitHub, GitLab's commit `author`/`committer` metadata is not cryptographically authenticated by default — anyone with push access can set arbitrary author identity in their local git config. Without enforcing signed commits, there is no reliable way to prove which developer actually authored a given commit, which weakens forensic investigation after an incident, makes it easier for an attacker (e.g., using a stolen access token or a compromised CI runner) to impersonate a trusted developer in the commit log, and undermines any compliance/audit process that depends on verifiable authorship. Rejecting unsigned commits at push time (server-side enforcement, not just client-side convention) ensures every commit in the repository's history carries a cryptographically verifiable identity.

## How Checkov evaluates this
`RejectUnsignedCommits` is a `BaseResourceValueCheck` inspecting `push_rules[0].reject_unsigned_commits`:
- **FAIL** if the `push_rules` block (or `reject_unsigned_commits` within it) is missing (`missing_block_result=FAILED` — unsigned commits are accepted by default).
- **PASS** only if `reject_unsigned_commits` is explicitly `true`.
- **FAIL** if `reject_unsigned_commits` is explicitly `false`.

## Non-compliant example
```hcl
resource "gitlab_project" "app" {
  name             = "payments-service"
  visibility_level = "private"

  push_rules {
    reject_unsigned_commits = false
    prevent_secrets         = true
  }
}
```

## Remediated example
```hcl
resource "gitlab_project" "app" {
  name             = "payments-service"
  visibility_level = "private"

  push_rules {
    reject_unsigned_commits = true   # fix: reject any commit without a valid signature
    prevent_secrets         = true
  }
}
```

## Remediation steps
1. Add `reject_unsigned_commits = true` inside a `push_rules` block on every `gitlab_project` resource (note: GitLab push rules generally require a Premium/Ultimate license tier).
2. Ensure every developer and automation account that pushes to the project has GPG or SSH commit signing configured and their public key registered in their GitLab profile — otherwise enabling this will immediately block their pushes.
3. Roll out with a communication/onboarding step, since this is a hard server-side block, not a warning — unprepared developers/CI bots will be unable to push until they configure signing.
4. Combine with `CKV_GLB_1` (2 approvals) and `CKV_GLB_2` (no force push) for a comprehensive integrity control set: signed commits establish authorship, approvals establish review, and force-push prevention preserves history.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gitlab/RejectUnsignedCommits.py)
- [Terraform GitLab provider: gitlab_project (push_rules)](https://registry.terraform.io/providers/gitlabhq/gitlab/latest/docs/resources/project)
- [GitLab docs: Signed commits](https://docs.gitlab.com/ee/user/project/repository/signed_commits/)
