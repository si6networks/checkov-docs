# CKV_TF_2: Ensure Terraform module sources use a tag with a version number

## Severity
**HIGH** (score: 7.5/10)

Using a semantic version tag is a materially weaker supply-chain control than a commit hash (tags can be moved or deleted), so this check reduces but does not close the risk of unexpected upstream module changes.

## Summary
This check fails when a Terraform `module` block references a remote git source that is neither pinned to a commit hash nor to a semantic-version tag (e.g. `v1.2.3`), and (for registry-style sources) has no `version` constraint set.

## Applicability
- **IaC framework:** Terraform
- **Check type:** module check — applies to any `module` block, independent of provider
- **Entities:** `module` (all Terraform module blocks with a remote source)

## Why it matters
This is a more lenient, complementary control to CKV_TF_1 (which demands a full commit hash). It addresses the same class of supply-chain risk — modules whose source can silently change underneath you — but accepts a semantic-version tag as adequate protection when a full commit hash isn't used. Referencing a module by branch name (`?ref=main`) or with no ref/version at all means:
- The exact code fetched at `terraform init` time is not fixed and can change without any change to your own repository, defeating code review and change-tracking processes.
- A compromised upstream branch or an unreviewed force-push can inject malicious Terraform code (which can create backdoored IAM roles, disable encryption, open network access, exfiltrate secrets via provisioners, etc.) directly into your infrastructure with no visible diff on your side.
- Builds become non-reproducible: re-running the same configuration at different times can provision different infrastructure.

Pinning to a version tag is weaker than a commit hash (tags can in principle be moved/deleted and recreated to point elsewhere, whereas a commit hash is content-addressed and immutable), but it is still vastly better than an unpinned branch reference because most registries/hosts treat tags as append-only in practice and it gives you a clear, auditable version identifier to track and update deliberately.

## How Checkov evaluates this
The check (`RevisionVersionTag`) first delegates to the stricter `RevisionHash` (CKV_TF_1) check:
- If that check already **PASSES** (commit-hash-pinned) or returns `UNKNOWN` (local module path starting with `./` or `../`), this check inherits the same result.
- Otherwise, it inspects the `source`:
  - If the source is a recognized git source (`is_git_source`), it checks whether the source contains `?ref` or `&ref` **and** matches the regex `[?&](ref=).*(\d\.\d).*` — i.e., the ref value must contain a version-like pattern with at least one `digit.digit` sequence (e.g. `v1.2`, `2.0.1`). If so, it **PASSES**.
  - If the source is not a git-style source (e.g., a Terraform Registry module), it instead checks whether the module block has a separate `version` argument set. If `version` is present, it **PASSES**.
- If none of these conditions hold, the check **FAILS**.

## Non-compliant example
```hcl
module "cloud_storage" {
  source = "github.com/terraform-google-modules/terraform-google-cloud-storage//modules/simple_bucket?ref=main"

  project_id = var.project_id
  name       = "app-artifacts"
}
```

## Remediated example
```hcl
module "cloud_storage" {
  source = "github.com/terraform-google-modules/terraform-google-cloud-storage//modules/simple_bucket?ref=v6.1.1"

  project_id = var.project_id
  name       = "app-artifacts"
}
```

Or, for a Terraform Registry module, pin an explicit `version`:
```hcl
module "cloud_storage" {
  source  = "terraform-google-modules/cloud-storage/google//modules/simple_bucket"
  version = "6.1.1"

  project_id = var.project_id
  name       = "app-artifacts"
}
```

## Remediation steps
1. Prefer a full commit hash (see CKV_TF_1) where possible — it is the strongest guarantee of immutability.
2. If a commit hash is impractical, pin the module's git `ref=` to a semantic-version release tag (must contain a `digit.digit` pattern, e.g. `v1.2.3` or `2.0`).
3. For modules sourced from the Terraform Registry (or any source supporting the separate `version` argument), always set an explicit `version` constraint rather than leaving it unconstrained.
4. Avoid referencing `main`, `master`, `latest`, or other floating branch names in module sources.
5. Periodically review and bump pinned versions/hashes as part of a deliberate update process (e.g., via Renovate/Dependabot) rather than relying on automatic drift.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/module/generic/RevisionVersionTag.py)
- [Terraform module versions documentation](https://developer.hashicorp.com/terraform/language/modules/syntax#version)
