# CKV_GCP_78: Ensure Cloud storage has versioning enabled
## Severity
**LOW** (score: 2.0/10)

Missing bucket versioning removes recovery capability after accidental or malicious overwrite/delete, harming integrity and incident-response ability without itself being an exploitable entry point.

## Summary
This check ensures a `google_storage_bucket` has object versioning enabled, so prior versions of objects are retained rather than being permanently overwritten or deleted.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_storage_bucket`

## Why it matters
Without versioning, an overwrite or delete of an object in Cloud Storage is destructive and irreversible via the API — the previous content is gone. This creates both a security and reliability exposure: a compromised credential or misbehaving automation (e.g., a buggy deploy script, an attacker with write access, or accidental `gsutil rm`) can silently destroy or corrupt data with no built-in recovery path. This is particularly serious for buckets holding audit logs, backups, Terraform state, or other data whose integrity matters for incident response — if such an object is tampered with or deleted, investigators lose the ability to reconstruct what happened. Versioning preserves noncurrent object generations, giving a recovery and forensic path even after unauthorized or accidental modification/deletion.

## How Checkov evaluates this
Checkov inspects `versioning[0].enabled` on the `google_storage_bucket` resource, expecting it to be truthy (`true`) to PASS. If the `versioning` block is missing, or `enabled` is `false`/absent, the check FAILS.

## Non-compliant example
```hcl
resource "google_storage_bucket" "bucket" {
  name     = "my-app-artifacts"
  location = "US"
  # versioning block omitted -> object history not retained
}
```

## Remediated example
```hcl
resource "google_storage_bucket" "bucket" {
  name     = "my-app-artifacts"
  location = "US"

  versioning {
    enabled = true
  }
}
```

## Remediation steps
1. Add a `versioning { enabled = true }` block to each `google_storage_bucket` resource that holds data worth protecting from accidental/malicious overwrite or deletion.
2. Pair versioning with a lifecycle rule (`lifecycle_rule`) to expire old noncurrent versions after a retention period, to avoid unbounded storage cost growth.
3. For buckets holding highly sensitive audit data, consider also enabling a retention policy / Bucket Lock for immutability guarantees stronger than versioning alone.
4. Enabling versioning is a live, non-disruptive update — it does not require bucket recreation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudStorageVersioningEnabled.py)
- [Google Cloud: Object versioning](https://cloud.google.com/storage/docs/object-versioning)
