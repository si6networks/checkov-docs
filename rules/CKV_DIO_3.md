# CKV_DIO_3: Ensure the Spaces bucket is private

## Severity
**HIGH** (score: 7.5/10)

Setting a Spaces bucket ACL to public-read exposes its entire object contents to anyone on the internet, a broad and direct confidentiality risk for whatever data the bucket holds.

## Summary
This check ensures a DigitalOcean Spaces bucket's ACL is not set to `public-read`, preventing the bucket's contents from being publicly listable/readable by default.

## Applicability
Terraform resource type `digitalocean_spaces_bucket` (DigitalOcean provider). Specifically inspects the `acl` attribute.

## Why it matters
Spaces (DigitalOcean's S3-compatible object storage) buckets configured with `acl = "public-read"` allow anyone on the internet to list and download every object in the bucket by default, unless overridden at the object level. This is a very common source of real-world data breaches — accidental exposure of backups, database dumps, log files, user uploads, or credentials stored in object storage. Defaulting to a private ACL and granting access explicitly (via signed URLs, bucket policies scoped to specific paths, or CDN configurations) follows least-privilege principles and avoids the class of misconfiguration that has repeatedly led to large-scale cloud storage leaks.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` on the `acl` attribute, with the forbidden value `"public-read"`. It's configured with `missing_attribute_result=CheckResult.PASSED`, meaning if `acl` is not set at all, the check PASSES (the DigitalOcean provider's default ACL is `private`). The check FAILS only when `acl` is explicitly set to `"public-read"`. Any other explicit value (e.g. `"private"`) also PASSES.

## Non-compliant example
```hcl
resource "digitalocean_spaces_bucket" "uploads" {
  name   = "example-uploads"
  region = "nyc3"
  acl    = "public-read"
}
```

## Remediated example
```hcl
resource "digitalocean_spaces_bucket" "uploads" {
  name   = "example-uploads"
  region = "nyc3"
  acl    = "private"
}
```

## Remediation steps
1. Remove `acl = "public-read"` from the `digitalocean_spaces_bucket` resource, or set it explicitly to `"private"`.
2. Audit existing objects in the bucket for any that were uploaded with a public object-level ACL independent of the bucket default, since object ACLs can override the bucket default.
3. If public access to specific assets is genuinely required (e.g., serving static website assets or public downloads), scope that exposure narrowly — use per-object ACLs, a CDN in front of the bucket, or a bucket policy limited to a specific path prefix — rather than making the whole bucket public.
4. For temporary/authenticated access, use pre-signed URLs instead of a public ACL.
5. Re-run `terraform plan`/`checkov` to confirm the resource now passes, and verify with `s3cmd`/`aws s3api` (Spaces is S3-API-compatible) that anonymous `ListObjects`/`GetObject` calls are now denied.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/digitalocean/SpacesBucketPublicRead.py
- DigitalOcean Terraform provider docs: https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/spaces_bucket
