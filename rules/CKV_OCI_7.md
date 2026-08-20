# CKV_OCI_7: Ensure OCI Object Storage bucket can emit object events

## Severity
**LOW** (score: 2.0/10)

Not emitting object storage events limits downstream event-driven security automation and audit trail granularity, a monitoring gap rather than a direct exposure.

## Summary
This check ensures that an OCI Object Storage bucket (`oci_objectstorage_bucket`) is configured to emit object-level events (create, update, delete) to the OCI Events service.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `oci_objectstorage_bucket`

## Why it matters
Without object events enabled, there is no automated, near-real-time notification pipeline reacting to changes in bucket contents. This matters for security in two ways: first, it prevents building automated detection/response — e.g., an event-driven rule that scans newly uploaded objects for malware, validates object ACLs, or alerts on unexpected deletions (a common indicator of ransomware or an insider threat tampering with evidence/backups). Second, from a governance standpoint, object events are often the backbone of audit and data-lineage pipelines (e.g., feeding a SIEM or triggering compliance workflows on sensitive data uploads). Leaving this disabled means object-level activity is only visible retrospectively through Audit logs (if enabled) rather than actionable in real time.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `object_events_enabled` attribute on `oci_objectstorage_bucket`. The check passes only if this is explicitly `true`; it fails if the attribute is absent or `false`.

## Non-compliant example
```hcl
resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id = var.compartment_id
  namespace      = var.object_storage_namespace
  name           = "app-artifacts"
  # object_events_enabled omitted - defaults to false, no event emission
}
```

## Remediated example
```hcl
resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id       = var.compartment_id
  namespace            = var.object_storage_namespace
  name                 = "app-artifacts"
  object_events_enabled = true
}
```

## Remediation steps
1. Set `object_events_enabled = true` on the `oci_objectstorage_bucket` resource.
2. Create OCI Events rules (`oci_events_rule`) that filter on the bucket's object lifecycle events (e.g., `com.oraclecloud.objectstorage.deleteobject`) and route them to a target such as Notifications, Functions, or Streaming.
3. This is a non-disruptive, in-place update to the bucket's configuration.
4. Consider combining with bucket-level Audit and retention rules for a complete detection and forensic trail.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/ObjectStorageEmitEvents.py)
