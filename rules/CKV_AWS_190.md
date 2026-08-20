# CKV_AWS_190: Ensure lustre file systems is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

This enforces customer-managed KMS keys for Lustre file systems rather than encryption presence, so the gap is reduced control over key rotation/revocation for already-encrypted data.

## Summary
This check requires that an `aws_fsx_lustre_file_system` resource specify a customer-managed KMS key (`kms_key_id`) for at-rest encryption instead of the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_fsx_lustre_file_system`
- **Check type:** resource (attribute-value check)

## Why it matters
FSx for Lustre is typically used for high-performance computing and machine learning training workloads, often linked directly to S3 data repositories containing large training datasets or scientific/engineering data. Without a customer-managed key, the file system falls back to the AWS-owned default key, meaning your organization cannot enforce a dedicated key policy limiting which compute roles (e.g., specific HPC cluster or SageMaker training job roles) can decrypt the data, cannot centrally audit key usage, and cannot immediately revoke access by disabling the key. Since Lustre file systems are frequently ephemeral and spun up/torn down for batch jobs, having consistent CMK-based governance across all such file systems is important for maintaining a uniform data-access audit trail, especially when the underlying datasets are proprietary or regulated.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_fsx_lustre_file_system`. It expects `ANY_VALUE` — any non-empty value passes; absence of the attribute causes the check to FAIL.

## Non-compliant example
```hcl
resource "aws_fsx_lustre_file_system" "example" {
  storage_capacity            = 1200
  subnet_ids                  = [aws_subnet.example.id]
  deployment_type              = "SCRATCH_2"
  # kms_key_id not set -- uses AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "fsx" {
  description             = "CMK for FSx Lustre encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_fsx_lustre_file_system" "example" {
  storage_capacity = 1200
  subnet_ids        = [aws_subnet.example.id]
  deployment_type   = "SCRATCH_2"
  kms_key_id        = aws_kms_key.fsx.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy scoped to the compute cluster/training job roles that will mount the file system.
2. Set `kms_key_id` on the `aws_fsx_lustre_file_system` resource.
3. Note that `PERSISTENT_1`/`PERSISTENT_2` deployment types benefit most from CMK governance since they are long-lived; `SCRATCH` types are often ephemeral but should still be encrypted consistently per policy.
4. `kms_key_id` cannot be changed on an existing file system — this requires resource replacement (destroy/recreate), so apply this at initial provisioning rather than retrofitting a running cluster's storage.
5. Ensure the FSx service and consuming compute roles have `kms:Decrypt`/`kms:CreateGrant` permissions in the CMK's key policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LustreFSEncryptedWithCMK.py)
- [AWS FSx for Lustre encryption documentation](https://docs.aws.amazon.com/fsx/latest/LustreGuide/encryption-at-rest.html)
