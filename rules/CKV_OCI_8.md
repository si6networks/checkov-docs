# CKV_OCI_8: Ensure OCI Object Storage has versioning enabled

## Severity
**LOW** (score: 2.0/10)

Missing versioning on object storage increases risk of irreversible data loss or tampering (e.g., ransomware, accidental overwrite) but does not directly expose data to unauthorized parties.

## Summary
This check ensures that an OCI Object Storage bucket (`oci_objectstorage_bucket`) has object versioning enabled so prior versions of an object are retained rather than overwritten or lost.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `oci_objectstorage_bucket`

## Why it matters
Without versioning, every `PUT` or `DELETE` on an object is destructive and irreversible from within the bucket: an application bug, a compromised credential, a malicious insider, or ransomware that overwrites/deletes objects will permanently destroy the previous data with no built-in recovery mechanism. Versioning preserves every prior copy of an object, letting you restore to any previous state — including recovering from accidental overwrite, unauthorized tampering, or deletion. This is a core control for both operational resilience (accidental data loss) and security (recovery after a compromised account starts deleting or corrupting data), and is frequently a prerequisite for compliance-grade data retention and legal-hold requirements.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `versioning` attribute on `oci_objectstorage_bucket`. The check passes only if `versioning` is exactly the string `"Enabled"`; any other value (including the default `"Disabled"`, or the attribute being unset) fails the check.

## Non-compliant example
```hcl
resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id = var.compartment_id
  namespace      = var.object_storage_namespace
  name           = "app-artifacts"
  # versioning omitted - defaults to "Disabled"
}
```

## Remediated example
```hcl
resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id = var.compartment_id
  namespace      = var.object_storage_namespace
  name           = "app-artifacts"
  versioning     = "Enabled"
}
```

## Remediation steps
1. Set `versioning = "Enabled"` on the `oci_objectstorage_bucket` resource.
2. This is a non-disruptive change and can be applied to existing buckets without downtime.
3. Since versioning retains all historical object versions, pair it with a lifecycle policy (`oci_objectstorage_object_lifecycle_policy`) to expire old noncurrent versions and control storage cost growth.
4. Ensure application code that lists/deletes objects accounts for versioning semantics (e.g., deletes create a delete marker rather than immediately purging data).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/ObjectStorageVersioning.py)
