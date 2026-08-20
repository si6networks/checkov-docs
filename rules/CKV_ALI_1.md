# CKV_ALI_1: Alibaba Cloud OSS bucket accessible to public

## Severity
**CRITICAL** (score: 9.0/10)

A `public-read`/`public-read-write` OSS bucket ACL exposes every object to unauthenticated internet access (and potentially tampering or deletion), mirroring the pattern behind numerous large-scale cloud storage data breaches.

## Summary
This check ensures Alibaba Cloud OSS (Object Storage Service) buckets do not have their ACL set to `public-read` or `public-read-write`, whether configured directly on `alicloud_oss_bucket` or via a separate `alicloud_oss_bucket_acl` resource.

## Applicability
**Checkov framework(s):** `terraform`

Terraform. Applies to `alicloud_oss_bucket` and `alicloud_oss_bucket_acl` resources.

## Why it matters
An OSS bucket ACL of `public-read` allows anyone on the internet, without authentication, to list and download every object in the bucket; `public-read-write` additionally allows anyone to upload, overwrite, or delete objects. This is one of the most common and consequential cloud misconfigurations across every major cloud provider — publicly-readable buckets have repeatedly led to large-scale data breaches (leaked customer PII, credentials, internal documents, source code, and backups), and publicly-writable buckets can be abused to host malware, deface content, or pollute/destroy legitimate data. Because OSS bucket ACLs can be set either directly on the bucket resource or overridden by a separate `alicloud_oss_bucket_acl` resource (mirroring the AWS S3 bucket/bucket-acl split), it's easy for a bucket that starts private to accidentally become public through a later, easily overlooked resource.

## How Checkov evaluates this
Graph-based JSON policy (`OSSBucketPublic.json`). It requires the `alicloud_oss_bucket`'s own `acl` attribute to NOT be `public-read` or `public-read-write`, AND either:
1. The bucket has no connected `alicloud_oss_bucket_acl` resource (so only the bucket's own `acl` value matters), OR
2. The bucket IS connected to an `alicloud_oss_bucket_acl` resource, and that resource's `acl` attribute is also not `public-read`/`public-read-write` (the separate ACL resource, when present, is authoritative and is checked too).
It fails if either the bucket's own `acl` or its connected `oss_bucket_acl` resource sets ACL to `public-read` or `public-read-write`.

## Non-compliant example
```hcl
resource "alicloud_oss_bucket" "data" {
  bucket = "company-data-bucket"
  acl    = "public-read"    # anyone can list/download all objects
}
```

## Remediated example
```hcl
resource "alicloud_oss_bucket" "data" {
  bucket = "company-data-bucket"
  acl    = "private"        # only authenticated, authorized principals can access
}
```

## Remediation steps
1. Set `acl = "private"` on every `alicloud_oss_bucket` resource unless the bucket is intentionally hosting public static content (e.g. a public website's static assets).
2. Check for any separate `alicloud_oss_bucket_acl` resource referencing the same bucket and ensure its `acl` is also `private` — it overrides the bucket-level setting.
3. For buckets that legitimately need public read access (e.g. static website hosting), scope exposure narrowly: enable it only on a dedicated bucket containing solely public assets, never one that also stores sensitive/internal data.
4. Add bucket policies and, where available, Alibaba Cloud's public access block equivalent to prevent accidental future changes to ACL.
5. Audit existing buckets in the account for public ACLs already in place, since this Terraform check only covers configuration drift going forward, not runtime/console-made changes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/alicloud/OSSBucketPublic.json
