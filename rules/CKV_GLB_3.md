# CKV_GLB_3: Ensure GitLab prevent secrets is enabled
## Severity
**MEDIUM** (score: 5.0/10)

Disabling GitLab's push-based secret detection lets hardcoded credentials be committed and pushed into repository history without being flagged.

## Summary
This check ensures a GitLab project's push rules have the built-in "prevent secrets" feature enabled, which blocks pushes that appear to contain known file types/patterns commonly used for credentials and private keys.

## Applicability
Applies to Terraform configurations using the `gitlab` provider, specifically the `gitlab_project` resource, at the `push_rules[0].prevent_secrets` attribute.

## Why it matters
GitLab's `prevent_secrets` push rule server-side rejects pushes containing files that match known secret/credential patterns (e.g., `.pem`, `.ppk`, `id_rsa`, various cloud provider credential file formats) *before* they ever land in the repository. Without it, developers can accidentally commit and push private keys, service account files, or other credential material, and that material becomes part of the repository's permanent history the instant the push succeeds — visible to anyone with read access and effectively impossible to fully purge (a `git rebase`/history rewrite is needed, and the secret must still be treated as compromised and rotated). Because most secret leaks happen via ordinary developer mistakes rather than sophisticated attacks, a server-side preventive push rule is a meaningfully cheap and effective control, catching the leak at push time rather than relying entirely on after-the-fact secret-scanning and remediation.

## How Checkov evaluates this
`PreventSecretsEnabled` is a `BaseResourceValueCheck` inspecting `push_rules[0].prevent_secrets`:
- **FAIL** if the `push_rules` block (or `prevent_secrets` within it) is missing (`missing_block_result=FAILED` — the GitLab default is that this protection is off).
- **PASS** only if `prevent_secrets` is explicitly `true`.
- **FAIL** if `prevent_secrets` is explicitly `false`.

## Non-compliant example
```hcl
resource "gitlab_project" "app" {
  name             = "payments-service"
  visibility_level = "private"

  push_rules {
    prevent_secrets      = false
    deny_delete_tag      = true
  }
}
```

## Remediated example
```hcl
resource "gitlab_project" "app" {
  name             = "payments-service"
  visibility_level = "private"

  push_rules {
    prevent_secrets      = true   # fix: block pushes containing known secret file patterns
    deny_delete_tag      = true
  }
}
```

## Remediation steps
1. Add a `push_rules` block with `prevent_secrets = true` to every `gitlab_project` resource (note: GitLab push rules generally require a Premium/Ultimate license tier).
2. Note this is a pattern-based, best-effort filter (known filenames/extensions like private keys) — it is not a full-content secret scanner. Pair it with GitLab's Secret Detection (SAST) scanning in CI, or a dedicated tool (e.g., gitleaks, TruffleHog), to catch secrets embedded in arbitrary file contents that don't match the built-in filename patterns.
3. If a secret was ever pushed before this rule was enabled, treat it as compromised: rotate the credential and purge it from history (`git filter-repo` or GitLab's repository cleanup tooling), since enabling the rule going forward does not retroactively remove existing exposure.
4. Combine with `CKV_GLB_4` (reject unsigned commits) and branch protection settings for a layered defense against unauthorized/unreviewed pushes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gitlab/PreventSecretsEnabled.py)
- [Terraform GitLab provider: gitlab_project (push_rules)](https://registry.terraform.io/providers/gitlabhq/gitlab/latest/docs/resources/project)
- [GitLab docs: Push rules](https://docs.gitlab.com/ee/user/project/repository/push_rules.html)
