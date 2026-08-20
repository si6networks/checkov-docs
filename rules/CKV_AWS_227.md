# CKV_AWS_227: Ensure KMS key is enabled

## Severity
**LOW** (score: 2.0/10)

A disabled KMS key breaks decrypt/encrypt operations for dependent resources (an availability failure), but it does not itself expose data or grant unintended access, so the direct exploitability is minimal.

## Summary
This check ensures that an AWS KMS (Key Management Service) key resource is not left in a disabled state, which would make it unusable for encryption or decryption operations.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_kms_key`

## Why it matters
A KMS key that is disabled (`is_enabled = false`) cannot be used to encrypt or decrypt data, generate data keys, or perform any cryptographic operations. If any dependent resource — an S3 bucket, EBS volume, RDS instance, Secrets Manager secret, etc. — relies on that key for server-side encryption, disabling the key silently breaks access to that data at read/write time, potentially causing an outage. It can also indicate a forgotten manual action (someone disabled the key during an incident and never re-enabled it) or a misconfiguration introduced via copy-pasted Terraform. From a security-hygiene perspective, an unintentionally disabled key can also mask the fact that encryption is not actually happening, giving a false sense of protection while a resource silently falls back to a default (e.g. AWS-managed) key or errors out.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `is_enabled` attribute of the `aws_kms_key` resource block.
- If the `is_enabled` attribute is **absent entirely**, the check treats this as a PASS (`missing_block_result=CheckResult.PASSED`) — Terraform's own default for `is_enabled` is `true`, so omitting it is safe.
- If `is_enabled` is explicitly set to `false`, the check **FAILS**.
- If `is_enabled` is explicitly set to `true`, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_kms_key" "app_key" {
  description = "KMS key for application data encryption"
  is_enabled  = false
}
```

## Remediated example
```hcl
resource "aws_kms_key" "app_key" {
  description = "KMS key for application data encryption"
  is_enabled  = true
}
```

## Remediation steps
1. Locate the `aws_kms_key` resource(s) flagged by Checkov.
2. Either remove the `is_enabled` attribute entirely (defaults to `true`) or set it explicitly to `true`.
3. If the key was intentionally disabled (e.g. during key rotation/decommission), verify no active resource still references it via `kms_key_id`/`kms_master_key_id` before disabling, and consider scheduling key deletion (`aws_kms_key` supports `deletion_window_in_days`) instead of leaving it disabled indefinitely.
4. Re-run `terraform plan` — re-enabling a key is a metadata-only change and does not require resource replacement.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KMSKeyIsEnabled.py)
- [AWS KMS: Enabling and disabling keys](https://docs.aws.amazon.com/kms/latest/developerguide/enabling-keys.html)
