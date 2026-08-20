# CKV_YC_3: Ensure storage bucket is encrypted.

## Severity
**HIGH** (score: 7.5/10)

An Object Storage bucket without server-side encryption configured leaves data at rest unprotected, so any bucket-level or backend compromise directly exposes the underlying objects in plaintext.

## Summary
This check ensures that a Yandex Cloud Object Storage bucket (`yandex_storage_bucket`) has server-side encryption configured with a KMS master key, rather than being left without encryption-at-rest configuration.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `yandex_storage_bucket`
- **Check type:** resource (value check, `ANY_VALUE` expected)

## Why it matters
Object Storage buckets frequently hold sensitive data — application backups, logs, user uploads, database exports, secrets bundles. Without server-side encryption configured with a customer-managed KMS key, data at rest relies solely on whatever default protections the storage layer provides, and the organization loses control over key management, rotation, and revocation. If a bucket's underlying storage media, snapshot, or misconfigured access control is ever exposed, unencrypted (or platform-default-encrypted) data is immediately readable, whereas KMS-backed encryption means access to the data also requires access to (and decrypt permission on) the KMS key — providing an additional layer of access control and enabling centralized key rotation, auditing (via KMS access logs), and the ability to instantly render data unreadable by disabling/destroying the key. This is also frequently a compliance requirement (PCI-DSS, HIPAA, SOC 2, ISO 27001) for data at rest.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute path:
```
server_side_encryption_configuration/[0]/rule/[0]/apply_server_side_encryption_by_default/[0]/kms_master_key_id
```
The expected value is `ANY_VALUE`, meaning the check **PASSES** as soon as `kms_master_key_id` is set to *any* non-empty value (a KMS key ID or ARN-like reference). If the `server_side_encryption_configuration` block, its nested `rule`/`apply_server_side_encryption_by_default` block, or the `kms_master_key_id` attribute is missing entirely, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_storage_bucket" "bad_example" {
  bucket = "my-app-data-bucket"
  # No server_side_encryption_configuration block at all
}
```

## Remediated example
```hcl
resource "yandex_kms_symmetric_key" "bucket_key" {
  name              = "bucket-encryption-key"
  default_algorithm = "AES_256"
  rotation_period   = "8760h"
}

resource "yandex_storage_bucket" "good_example" {
  bucket = "my-app-data-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # KMS key ID now set — this is the fix
        kms_master_key_id = yandex_kms_symmetric_key.bucket_key.id
        sse_algorithm      = "aws:kms"
      }
    }
  }
}
```

## Remediation steps
1. Create (or identify an existing) `yandex_kms_symmetric_key` resource to serve as the bucket's encryption key.
2. Add a `server_side_encryption_configuration` block to the `yandex_storage_bucket` resource with a `rule` containing `apply_server_side_encryption_by_default`, setting `kms_master_key_id` to the KMS key's ID and `sse_algorithm` to `"aws:kms"` (Yandex Object Storage's S3-compatible API uses this algorithm name for KMS-backed SSE).
3. Grant the storage service's principal the necessary `kms.keys.encrypterDecrypter` role on the KMS key so it can perform encryption/decryption operations on behalf of the bucket.
4. Set an appropriate `rotation_period` on the KMS key (see CKV_YC_9) to ensure keys are rotated periodically.
5. Note: enabling SSE on an existing bucket only affects objects written after the change — existing objects are not retroactively encrypted; consider a re-upload/copy-in-place strategy if full-bucket encryption is required immediately.
6. Re-run Checkov to confirm `kms_master_key_id` is populated.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/ObjectStorageBucketEncryption.py
