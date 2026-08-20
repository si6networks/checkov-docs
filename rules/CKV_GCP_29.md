# CKV_GCP_29: Ensure that Cloud Storage buckets have uniform bucket-level access enabled
## Severity
**LOW** (score: 2.0/10)

Without uniform bucket-level access, object-level ACLs can override IAM policy and inconsistently grant access to individual objects, creating a risk of accidental exposure even when bucket-level IAM looks correctly restricted.

## Summary
This check fails when a `google_storage_bucket` does not set `uniform_bucket_level_access = true`, leaving the bucket able to use legacy object-level ACLs alongside IAM.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_storage_bucket`
- **Check type:** resource

## Why it matters
Without uniform bucket-level access, GCS buckets support two parallel, independently-editable access-control systems: IAM (bucket/project-level) and legacy ACLs (per-object and per-bucket). This dual model is a well-documented source of misconfiguration: an administrator can lock down IAM at the bucket level and believe the bucket is private, while an individual object still carries a permissive legacy ACL (e.g., applied by an old script, a `gsutil acl` command, or a default object ACL) making that specific object public or group-readable — invisible unless you separately audit ACLs. Enabling uniform bucket-level access disables legacy ACLs entirely and makes IAM the single source of truth, closing this "split-brain" gap and making access auditing tractable.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on the key `uniform_bucket_level_access`:
- **PASS** — `uniform_bucket_level_access` is set to `true`.
- **FAIL** — the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "google_storage_bucket" "auth0_logs" {
  name     = "auth0-logs-bucket"
  location = "US"
  # uniform_bucket_level_access omitted (defaults to false) -> FAILS
}
```

## Remediated example
```hcl
resource "google_storage_bucket" "auth0_logs" {
  name                        = "auth0-logs-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}
```

## Remediation steps
1. Add `uniform_bucket_level_access = true` to every `google_storage_bucket` resource.
2. Before enabling on an existing bucket, audit and migrate any legacy per-object ACL grants to equivalent IAM bindings (`roles/storage.objectViewer`, etc.) — once uniform access is enabled, existing object ACLs are simply ignored, so verify nothing relied on an ACL-only grant.
3. GCP allows switching this setting on for up to 90 days after bucket creation without restriction; after that, switching from uniform to fine-grained access has additional constraints — check current bucket state with `gsutil bucketpolicyonly get gs://<bucket>` before assuming a simple toggle.
4. This is generally an in-place update with no bucket recreation required, but coordinate with anyone depending on ACL-based access for the affected bucket.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleStorageBucketUniformAccess.py
- GCP docs: https://cloud.google.com/storage/docs/uniform-bucket-level-access
