# CKV_TF_1: Ensure Terraform module sources use a commit hash

## Severity
**MEDIUM** (score: 5.0/10)

Pinning a module source to a mutable ref (branch/tag) rather than an immutable commit hash allows the upstream module content to change without notice, opening a supply-chain path for malicious or compromised code to be silently pulled into the deployment.

## Summary
This check fails when a Terraform `module` block references a remote (e.g., git) source without pinning it to an immutable commit hash via a `?ref=<sha>` query parameter.

## Applicability
- **IaC framework:** Terraform
- **Check type:** module check — applies to any `module` block regardless of provider, since it inspects only the `source` attribute
- **Entities:** `module` (all Terraform module blocks with a remote git-style `source`)

## Why it matters
This is a supply-chain security control. When a module `source` points to a branch name (e.g. `?ref=main`) or a mutable tag, the exact code that gets pulled into your infrastructure at `terraform init`/`apply` time can change without any corresponding change in your own repository. This creates several risks:
- **Supply-chain tampering:** if an attacker compromises the upstream module repository (or a maintainer's account) and pushes malicious commits to a branch you reference, your next `terraform apply` silently pulls in that malicious code — with no diff, PR, or review in your own codebase to catch it.
- **Non-reproducible builds:** the same Terraform configuration can produce different infrastructure at different times, breaking auditability and making incident forensics ("what code created this resource?") unreliable.
- **Unreviewed drift:** upstream module changes bypass your organization's code review process entirely, since nothing in your version control shows the change happened.

Pinning to a full commit SHA guarantees the exact tree of code fetched is immutable and content-addressed — any tampering with that commit would require rewriting git history (and change the hash), which is far more visible and detectable than force-pushing a branch or moving a tag.

## How Checkov evaluates this
The check (`RevisionHash`) inspects the `source` argument of a `module` block:
- If the source starts with `./` or `../` (a local path), the result is `UNKNOWN` — local modules can't be pinned to a commit hash and are exempted.
- Otherwise, it looks for `?ref=` in the source string and then applies the regex `\?(ref=)(?P<commit_id>([0-9a-f]{5,40}))` to confirm the `ref` value looks like a hex commit hash (5–40 hex characters).
- If both conditions are met, the check **PASSES**.
- Otherwise (no `?ref=`, or `ref=` points to something that isn't a hex string of the right length, e.g. a branch name or semantic version tag like `v1.2.3`), the check **FAILS**.

## Non-compliant example
```hcl
module "gke_workload_identity" {
  source = "github.com/terraform-google-modules/terraform-google-kubernetes-engine//modules/workload-identity?ref=main"

  project_id = var.project_id
  name       = "app-sa"
}
```

## Remediated example
```hcl
module "gke_workload_identity" {
  source = "github.com/terraform-google-modules/terraform-google-kubernetes-engine//modules/workload-identity?ref=2a823341d1366046d067e65d4dabb4c22e58fc4f"

  project_id = var.project_id
  name       = "app-sa"
}
```

## Remediation steps
1. Identify the current commit hash of the module version you intend to use (e.g. `git ls-remote <repo> <branch-or-tag>` or look up the commit associated with the release tag on GitHub).
2. Replace the `ref=` value in the module `source` URL with the full 40-character (or at least 5+ character) commit SHA.
3. For vendored/external modules under `.external_modules/`, regenerate or re-vendor them using a pinned commit reference rather than a branch or mutable tag.
4. Set up a process (e.g., Dependabot, Renovate, or a scheduled CI job) to periodically check for and propose updates to these pinned hashes, since pinning trades automatic updates for security — you must now manually/automatically bump the hash to get upstream fixes.
5. Note: CKV_TF_2 is a more lenient companion check that also accepts a semantic-version tag (e.g. `?ref=v1.2.3`) as sufficiently immutable for lower-risk cases; CKV_TF_1 requires a full commit hash specifically.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/module/generic/RevisionHash.py)
- [Terraform module sources documentation](https://developer.hashicorp.com/terraform/language/modules/sources)
