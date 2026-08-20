# CKV_OCI_10: Ensure OCI Object Storage is not Public
## Severity
**HIGH** (score: 7.5/10)

An Object Storage bucket configured for public read (or read-without-list) access exposes its contents to anyone on the internet, risking disclosure of any sensitive data stored in it.

## Summary
This check fails an OCI `oci_objectstorage_bucket` resource if its `access_type` is set to a value that grants public read access (`ObjectRead` or `ObjectReadWithoutList`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `oci_objectstorage_bucket`
- **Check type:** resource (negative value check)

## Why it matters
Object Storage buckets frequently hold application data, backups, logs, or user-uploaded content — some of which may be sensitive even if not obviously so at first glance (e.g., logs containing tokens, backups containing customer PII, or misconfigured uploads of internal documents). Setting `access_type` to `ObjectRead` or `ObjectReadWithoutList` makes bucket objects readable by anyone on the internet without authentication. This is one of the most common real-world cloud data breach vectors across all cloud providers: a bucket set to public — often "temporarily" for a demo or debugging session and never reverted — becomes indexed by scanners and search engines, exposing its contents to anyone who discovers the bucket name or URL, with no audit trail identifying who accessed the data.

## How Checkov evaluates this
The check is a `BaseResourceNegativeValueCheck` that inspects the `access_type` attribute of `oci_objectstorage_bucket`:
- **Forbidden values:** `"ObjectRead"`, `"ObjectReadWithoutList"`.
- **FAIL:** `access_type` is set to either of the forbidden values (public read, with or without the ability to list bucket contents).
- **PASS:** `access_type` is set to anything else (notably `"NoPublicAccess"`, the private/default-safe option) or is unset.

## Non-compliant example
```hcl
resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id = var.compartment_ocid
  namespace      = var.object_storage_namespace
  name           = "app-artifacts"
  access_type    = "ObjectRead"
}
```

## Remediated example
```hcl
resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id = var.compartment_ocid
  namespace      = var.object_storage_namespace
  name           = "app-artifacts"
  access_type    = "NoPublicAccess"
}
```

## Remediation steps
1. Set `access_type = "NoPublicAccess"` on the bucket unless there is a deliberate, documented business need for public content distribution.
2. If public access truly is required (e.g., serving static website assets), scope it narrowly: use a dedicated bucket containing only the intended public content, and consider fronting it with a CDN plus pre-authenticated requests or object-level policies instead of bucket-wide public access.
3. For sharing specific objects temporarily, use OCI's Pre-Authenticated Requests (PARs) which grant time-bound, scoped access to specific objects rather than making the whole bucket public.
4. Audit existing buckets for `access_type != "NoPublicAccess"` across all compartments, since this is commonly discovered by external scanners.
5. Enable Object Storage access logging/Cloud Guard detectors for public bucket exposure as an ongoing safety net.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/ObjectStoragePublic.py)
- [OCI Object Storage bucket visibility documentation](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm)
