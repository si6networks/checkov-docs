# CKV_ALI_6: Ensure OSS bucket is encrypted with Customer Master Key
## Severity
**MEDIUM** (score: 5.0/10)

Using default OSS encryption instead of a customer-managed KMS key weakens key-management control over bucket data but the data is still encrypted at rest by default AliCloud-managed keys.

## Summary
This check ensures that an Alibaba Cloud OSS (Object Storage Service) bucket's server-side encryption is configured with a Customer Master Key (CMK) from KMS, rather than relying solely on a platform-managed key or no key reference at all.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `alicloud_oss_bucket`

## Why it matters
OSS supports server-side encryption using either Alibaba Cloud's default/managed key or a customer-managed KMS key (CMK). Using a CMK gives the data owner direct control over the encryption key's lifecycle: they can rotate it, restrict who may use it via KMS access policies, audit every decrypt operation, and revoke access (effectively "shredding" the data) by disabling or deleting the key — none of which is possible with a fully platform-managed key. For buckets holding sensitive or regulated data, the ability to independently control and audit key usage is often a compliance requirement (e.g., a "customer-managed keys" or "bring your own key" mandate), and it also limits the blast radius if the cloud provider's own key-management infrastructure is ever compromised, since the customer retains ultimate authority over key material.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute path `server_side_encryption_rule/[0]/kms_master_key_id` on `alicloud_oss_bucket`, using `ANY_VALUE` as the expected value (i.e., it just needs to be non-empty/present).
- **FAIL** if the `server_side_encryption_rule` block is absent, or `kms_master_key_id` is not set within it.
- **PASS** if `server_side_encryption_rule { kms_master_key_id = "<any non-empty value>" }` is present.

## Non-compliant example
```hcl
resource "alicloud_oss_bucket" "example" {
  bucket = "example-bucket"

  server_side_encryption_rule {
    sse_algorithm = "KMS"
    # kms_master_key_id not set -> falls back to platform default key
  }
}
```

## Remediated example
```hcl
resource "alicloud_oss_bucket" "example" {
  bucket = "example-bucket"

  server_side_encryption_rule {
    sse_algorithm     = "KMS"
    kms_master_key_id = alicloud_kms_key.example.id  # <-- added: uses a customer-managed KMS key
  }
}
```

## Remediation steps
1. Provision (or reference an existing) `alicloud_kms_key` resource for the bucket to use.
2. Set `kms_master_key_id` inside the bucket's `server_side_encryption_rule` block to that key's ID.
3. Define an appropriate KMS key policy restricting who can use/administer the key, and enable key rotation per your organization's key-management standards.
4. Note: changing encryption settings does not retroactively re-encrypt existing objects — for full coverage, plan a re-upload/copy-in-place of pre-existing objects so they are encrypted under the new CMK.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/OSSBucketEncryptedWithCMK.py)
