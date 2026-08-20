# CKV_AWS_294: Ensure CloudTrail Event Data Store uses CMK
## Severity
**LOW** (score: 2.0/10)

This check verifies CloudTrail Event Data Store encryption uses a customer-managed KMS key; without a CMK the audit trail is still encrypted by AWS-managed keys, so the gap mainly weakens key-level access control over sensitive audit logs rather than leaving them wholly unencrypted.

## Summary
This check ensures that an `aws_cloudtrail_event_data_store` resource specifies a `kms_key_id`, so the stored audit event data is encrypted with a customer-managed KMS key rather than relying on default/no encryption configuration.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_cloudtrail_event_data_store`

## Why it matters
CloudTrail Event Data Stores hold your organization's audit trail — a record of every API call made across your AWS account(s), including who did what, when, and from where. This data is frequently the primary forensic evidence used during incident response and is itself a high-value target: an attacker who can read or tamper with audit logs can potentially cover their tracks. Using a customer-managed key (CMK) rather than leaving encryption unconfigured gives you control over the key policy (who can decrypt), enables key rotation on your own schedule, provides an audit trail of key usage via CloudTrail/KMS logs, and allows you to immediately revoke access (by disabling/deleting the CMK) if a breach is suspected — none of which is possible to the same degree without an explicit CMK.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check) using `ANY_VALUE` as the expected value. It inspects the `kms_key_id` attribute:
- **PASS** if `kms_key_id` is set to any non-empty value (any ARN).
- **FAIL** if `kms_key_id` is missing or empty.

## Non-compliant example
```hcl
resource "aws_cloudtrail_event_data_store" "audit" {
  name                          = "org-audit-events"
  multi_region_enabled          = true
  organization_enabled          = true
  retention_period              = 2557
  # kms_key_id not set -> check FAILS
}
```

## Remediated example
```hcl
resource "aws_kms_key" "cloudtrail_eds" {
  description             = "CMK for CloudTrail Event Data Store"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_cloudtrail_event_data_store" "audit" {
  name                  = "org-audit-events"
  multi_region_enabled  = true
  organization_enabled  = true
  retention_period      = 2557
  kms_key_id            = aws_kms_key.cloudtrail_eds.arn   # encrypt with CMK
}
```

## Remediation steps
1. Create (or reuse) a dedicated KMS key for CloudTrail event data, with `enable_key_rotation = true`.
2. Set `kms_key_id` on the `aws_cloudtrail_event_data_store` resource to that key's ARN or ID.
3. Ensure the KMS key policy grants the `cloudtrail.amazonaws.com` service principal the necessary `kms:GenerateDataKey*`, `kms:Decrypt`, and `kms:DescribeKey` permissions — CloudTrail will fail to write events if the key policy is too restrictive.
4. Note: enabling/changing `kms_key_id` on an existing Event Data Store may only re-encrypt future events, not retroactively re-encrypt already-stored events — check current AWS behavior before assuming full retroactive coverage.
5. Restrict who can manage or use the CMK via IAM and the key policy to enforce least privilege over audit log access.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudtrailEventDataStoreUsesCMK.py)
