# CKV_AWS_179: Ensure FSX Windows filesystem is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

This enforces customer-managed (vs. AWS-managed) KMS keys for FSx Windows file systems, so failure means weaker key governance and auditability over already-encrypted data, not an absence of encryption.

## Summary
This check requires that an `aws_fsx_windows_file_system` resource specify a customer-managed KMS key (`kms_key_id`) for at-rest encryption instead of relying on the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_fsx_windows_file_system`
- **Check type:** resource (attribute-value check)

## Why it matters
Amazon FSx for Windows File Server volumes are always encrypted at rest, but by default this uses an AWS-owned/managed KMS key that your organization does not control. FSx for Windows commonly backs SMB file shares used for user home directories, departmental shares, and application data — often containing PII or business-confidential documents. Using a CMK lets you enforce a dedicated key policy (limiting which IAM principals/roles can decrypt), independently audit key usage via CloudTrail, and revoke access instantly by disabling the key — none of which is possible with the default AWS-managed key. Many compliance frameworks (HIPAA, PCI-DSS, SOC 2, FedRAMP) require demonstrable control over encryption keys protecting regulated data, which the default key cannot satisfy.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `kms_key_id` attribute on `aws_fsx_windows_file_system`. It expects `ANY_VALUE` — any non-empty value passes. If the attribute is missing, the check FAILS because the file system falls back to the AWS-owned default key.

## Non-compliant example
```hcl
resource "aws_fsx_windows_file_system" "example" {
  active_directory_id = aws_directory_service_directory.example.id
  storage_capacity     = 300
  subnet_ids           = [aws_subnet.example.id]
  throughput_capacity  = 32
  # kms_key_id not set -- uses AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "fsx" {
  description             = "CMK for FSx Windows encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_fsx_windows_file_system" "example" {
  active_directory_id = aws_directory_service_directory.example.id
  storage_capacity     = 300
  subnet_ids           = [aws_subnet.example.id]
  throughput_capacity  = 32
  kms_key_id           = aws_kms_key.fsx.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy restricted to the principals that require file system access.
2. Set `kms_key_id` on the `aws_fsx_windows_file_system` resource to that key's ARN or ID.
3. Enable key rotation on the CMK.
4. Note: `kms_key_id` cannot be changed in place on an existing FSx Windows file system — this forces resource replacement. Plan a maintenance window and back up/restore data if retrofitting an existing deployment.
5. Confirm the FSx service role and any consuming IAM principals have the necessary `kms:Decrypt`/`kms:CreateGrant` permissions in the CMK's key policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/FSXWindowsFSEncryptedWithCMK.py)
- [AWS FSx for Windows File Server encryption documentation](https://docs.aws.amazon.com/fsx/latest/WindowsGuide/encryption-at-rest.html)
