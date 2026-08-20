# CKV_AWS_178: Ensure fx ontap file system is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

The check only verifies that a customer-managed KMS key is used for FSx ONTAP encryption rather than checking for encryption at all, so the gap is reduced key-control/auditability (rotation, revocation, cross-account access) rather than data being stored unencrypted.

## Summary
This check requires that an `aws_fsx_ontap_file_system` resource specify a customer-managed KMS key (`kms_key_id`) rather than relying on the AWS-managed default key for at-rest encryption.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_fsx_ontap_file_system`
- **Check type:** resource (attribute-value check)

## Why it matters
Amazon FSx for NetApp ONTAP file systems are always encrypted at rest, but by default AWS uses an AWS-owned/AWS-managed KMS key. Using a customer managed key (CMK) instead gives your organization direct control over the key lifecycle: you can define your own key policy, restrict which IAM principals may use it, enable/disable the key, rotate it on your own schedule, and — critically — revoke access to the key (e.g., during an incident or offboarding) to render the data cryptographically inaccessible. With an AWS-managed key, you cannot control or audit key usage at the same granularity, you cannot restrict which principals can decrypt the volume via key policy, and you lose the ability to immediately cut off access by disabling/deleting the key. This matters for FSx ONTAP because it commonly hosts NFS/SMB file shares carrying sensitive enterprise data, and compliance regimes (PCI-DSS, HIPAA, FedRAMP) frequently mandate CMK use with auditable key policies and CloudTrail logging of key operations.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the Terraform attribute `kms_key_id` on `aws_fsx_ontap_file_system`. The expected value is `ANY_VALUE`, meaning the check only requires that `kms_key_id` be set to *some* non-empty value (i.e., a KMS key ARN or ID is present) — it does not validate that the specific key is customer-managed vs. an alias for an AWS-managed key, but by definition supplying a real key ID/ARN here means the file system uses a CMK rather than the implicit AWS-owned key used when the attribute is omitted. If `kms_key_id` is absent, the check FAILS.

## Non-compliant example
```hcl
resource "aws_fsx_ontap_file_system" "example" {
  storage_capacity    = 1024
  subnet_ids          = [aws_subnet.example1.id, aws_subnet.example2.id]
  deployment_type     = "MULTI_AZ_1"
  throughput_capacity = 128
  preferred_subnet_id = aws_subnet.example1.id
  # kms_key_id not set -- uses AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "fsx" {
  description             = "CMK for FSx ONTAP encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_fsx_ontap_file_system" "example" {
  storage_capacity    = 1024
  subnet_ids          = [aws_subnet.example1.id, aws_subnet.example2.id]
  deployment_type     = "MULTI_AZ_1"
  throughput_capacity = 128
  preferred_subnet_id = aws_subnet.example1.id
  kms_key_id          = aws_kms_key.fsx.arn  # customer managed key
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key dedicated to FSx encryption, with a key policy scoped to the principals/roles that need access.
2. Add the `kms_key_id` argument to the `aws_fsx_ontap_file_system` resource, pointing to the CMK's ARN or key ID.
3. Enable automatic key rotation (`enable_key_rotation = true`) on the CMK for defense-in-depth.
4. Note: changing `kms_key_id` on an existing file system typically requires resource replacement (destroy/recreate) since FSx encryption keys are set at creation time — plan for a migration window and data restore from backup if applied retroactively.
5. Ensure the IAM role/user running Terraform, and the FSx service, have `kms:CreateGrant`, `kms:Decrypt`, and `kms:DescribeKey` permissions on the CMK's key policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/FSXOntapFSEncryptedWithCMK.py)
- [AWS FSx for ONTAP encryption documentation](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/encryption-at-rest.html)
