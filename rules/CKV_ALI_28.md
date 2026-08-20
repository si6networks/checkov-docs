# CKV_ALI_28: Ensure KMS Keys are enabled
## Severity
**LOW** (score: 2.0/10)

A disabled KMS key mainly creates an operational/availability risk (dependent encrypt/decrypt operations fail) rather than a direct confidentiality exposure, so this is primarily a hygiene and reliability check.

## Summary
This check verifies that Alibaba Cloud KMS keys are not left in a disabled state.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_kms_key`

## Why it matters
A disabled KMS key cannot be used to encrypt new data or decrypt existing ciphertext. If a key backing production data is inadvertently defined as disabled (or its status drifts to disabled and Terraform is not re-applied to catch it), any service depending on that key for encrypt/decrypt operations will fail — this is an availability/reliability risk as much as a security one, since applications may suddenly be unable to read data they previously wrote, or backup/restore workflows may silently break. Ensuring keys are provisioned in an enabled state avoids introducing an unintended outage or data-access failure through IaC.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on `alicloud_kms_key` with `missing_block_result=CheckResult.PASSED` (note: unlike CKV_ALI_27, an absent `status` attribute is treated as compliant here, since Alibaba Cloud KMS keys default to `Enabled` when created):
- Inspects the `status` attribute.
- FAILS only if `status` is explicitly set to something other than `"Enabled"` (e.g. `"Disabled"`).
- PASSES if `status = "Enabled"` or if `status` is not specified at all.

## Non-compliant example
```hcl
resource "alicloud_kms_key" "example" {
  description            = "example encryption key"
  pending_window_in_days = 7
  automatic_rotation      = "Enabled"
  status                  = "Disabled"   # <-- fails: key explicitly disabled
}
```

## Remediated example
```hcl
resource "alicloud_kms_key" "example" {
  description            = "example encryption key"
  pending_window_in_days = 7
  automatic_rotation      = "Enabled"
  status                  = "Enabled"    # <-- fix: key is enabled and usable
}
```

## Remediation steps
1. Locate any `alicloud_kms_key` resource with `status = "Disabled"`.
2. Remove the attribute (to default to enabled) or explicitly set `status = "Enabled"`.
3. If the key was intentionally disabled (e.g. as part of a planned deprecation/rotation-out process before scheduled deletion), verify no active workload still references it before leaving it disabled, and consider excluding that specific resource from this check with an inline Checkov suppression comment along with a justification.
4. This is an in-place status change; re-enabling a key that was disabled restores the ability to use it for encrypt/decrypt operations immediately.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/KMSKeyIsEnabled.py)
- [Alibaba Cloud KMS key resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/kms_key)
