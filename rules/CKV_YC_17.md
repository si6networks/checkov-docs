# CKV_YC_17: Ensure storage bucket does not have public access permissions

## Severity
**CRITICAL** (score: 9.3/10)

A storage bucket ACL or grant that allows public-read/public-read-write access (including the AllUsers group) can expose all objects in the bucket, including potentially sensitive data, to anyone on the internet.

## Summary
This check fails when a Yandex Object Storage bucket (`yandex_storage_bucket`) is configured with a public ACL (`public-read`/`public-read-write`) or an explicit grant to the `AllUsers` group.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `yandex_storage_bucket`

## Why it matters
Object storage misconfigurations are one of the most common and consequential sources of cloud data breaches — publicly readable (or writable) buckets have repeatedly led to mass exposure of customer data, credentials, backups, and internal documents across many organizations and cloud providers. A `public-read` ACL allows anyone on the internet, without authentication, to list and download every object in the bucket. `public-read-write` is even more severe, allowing anonymous users to also upload, overwrite, or delete objects — enabling data tampering, malware hosting, or ransomware-style destruction of bucket contents. An explicit grant to the S3-compatible `AllUsers` group URI has the same effect as a public ACL. Because Yandex Object Storage is S3-compatible, these buckets are also discoverable by the same automated internet-wide scanners that continuously search for open S3-compatible buckets across all cloud providers.

## How Checkov evaluates this
The check (`ObjectStorageBucketPublicAccess`) is a custom `BaseResourceCheck` (`scan_resource_conf`):
- If the resource has an `acl` attribute, and its value is `["public-read"]` or `["public-read-write"]`, the check **FAILS**.
- If the resource has a `grant` block, and its `uri` sub-attribute equals `["http://acs.amazonaws.com/groups/global/AllUsers"]` (the S3 "AllUsers" well-known group), the check **FAILS**.
- In all other cases (no public ACL, no AllUsers grant, e.g. `acl = "private"` or no `acl`/`grant` set at all), the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_storage_bucket" "example" {
  bucket = "company-reports"
  acl    = "public-read"  # bucket contents readable by anyone -- FAILS CKV_YC_17
}
```

Or equivalently via an explicit grant:
```hcl
resource "yandex_storage_bucket" "example" {
  bucket = "company-reports"

  grant {
    type        = "Group"
    permissions = ["READ"]
    uri         = "http://acs.amazonaws.com/groups/global/AllUsers"  # FAILS CKV_YC_17
  }
}
```

## Remediated example
```hcl
resource "yandex_storage_bucket" "example" {
  bucket = "company-reports"
  acl    = "private"  # no public access -- PASSES CKV_YC_17
}
```

## Remediation steps
1. Change `acl` to `"private"` (or remove it — Yandex Object Storage buckets default to private).
2. Remove any `grant` blocks that reference the `AllUsers` group URI, or restrict `grant` blocks to specific, identified grantees rather than the public group.
3. If content genuinely needs to be public (e.g., static website assets), scope public access narrowly — serve it via a CDN with signed URLs, a dedicated public-assets bucket separated from any bucket holding sensitive data, or object-level (not bucket-level) public grants limited to specific non-sensitive objects.
4. Enable bucket versioning and access logging so that any accidental exposure is detected and auditable.
5. Regularly audit all buckets in the account for public ACLs/grants as part of routine security review, since a single misconfigured bucket can undermine otherwise-strong controls elsewhere.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/ObjectStorageBucketPublicAccess.py)
- [Yandex Object Storage ACL documentation](https://yandex.cloud/en/docs/storage/concepts/acl)
