# CKV_AWS_171: Ensure EMR Cluster security configuration encryption is using SSE-KMS

## Severity
**LOW** (score: 2.0/10)

An EMR security configuration that doesn't enforce SSE-KMS leaves data processed or stored by the cluster unencrypted at rest, which is a meaningful confidentiality gap for the potentially large/sensitive datasets EMR typically handles.

## Summary
This check requires that an EMR security configuration's at-rest encryption for local disks/EBS is configured using SSE-KMS (server-side encryption with a KMS key), rather than a weaker or unspecified encryption mode.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_emr_security_configuration`

## Why it matters
EMR clusters process large datasets — frequently including sensitive business, customer, or regulated data — using EBS volumes and local instance storage for intermediate data (HDFS, shuffle spill, cached datasets). If the security configuration's encryption settings don't specify SSE-KMS, at-rest data may go unencrypted or use a locally-managed key that isn't integrated with AWS KMS's access control, auditing (CloudTrail key usage logging), and centralized key management/rotation capabilities.

Without SSE-KMS, an attacker who gains access to underlying EBS snapshots, terminated-instance storage remnants, or a misconfigured backup could read the cluster's working data in the clear, exposing data that was assumed to be protected because "the cluster is inside a VPC." SSE-KMS also allows fine-grained IAM+key-policy control over exactly which principals can decrypt cluster data, and provides an audit trail via CloudTrail for every key-usage event.

## How Checkov evaluates this
The check inspects the `configuration` attribute (a JSON-encoded security configuration string/object) on `aws_emr_security_configuration`. If `configuration` is absent entirely, the result is `UNKNOWN` (the check cannot determine the encryption setting). Otherwise, it takes the first `configuration` block and does a simple substring check: if the string `"SSE-KMS"` appears anywhere within the stringified configuration, the check **PASSES**; otherwise it **FAILS**. This is a coarse text-match rather than a structured parse of the JSON encryption fields, so any valid EMR security configuration containing the literal substring `SSE-KMS` (e.g. as the `EncryptionMode` for `AtRestEncryptionConfiguration`) will satisfy it.

## Non-compliant example
```hcl
resource "aws_emr_security_configuration" "emr_sec_config" {
  name = "emrSecurityConfig"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableInTransitEncryption = true
      EnableAtRestEncryption    = true
      AtRestEncryptionConfiguration = {
        S3EncryptionConfiguration = {
          EncryptionMode = "SSE-S3"
        }
        LocalDiskEncryptionConfiguration = {
          EncryptionKeyProviderType = "AwsKms"
          # No SSE-KMS mode referenced anywhere in this config
        }
      }
    }
  })
}
```

## Remediated example
```hcl
resource "aws_kms_key" "emr" {
  description = "CMK for EMR at-rest encryption"
}

resource "aws_emr_security_configuration" "emr_sec_config" {
  name = "emrSecurityConfig"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableInTransitEncryption = true
      EnableAtRestEncryption    = true
      AtRestEncryptionConfiguration = {
        S3EncryptionConfiguration = {
          EncryptionMode = "SSE-KMS"          # added
          AwsKmsKey      = aws_kms_key.emr.arn
        }
        LocalDiskEncryptionConfiguration = {
          EncryptionKeyProviderType = "AwsKms"
          AwsKmsKey                 = aws_kms_key.emr.arn
        }
      }
    }
  })
}
```

## Remediation steps
1. In the `configuration` JSON of `aws_emr_security_configuration`, set the relevant encryption mode field(s) (e.g. `S3EncryptionConfiguration.EncryptionMode`) to `"SSE-KMS"` and supply an `AwsKmsKey` ARN.
2. Ensure `LocalDiskEncryptionConfiguration` also references a KMS key (`EncryptionKeyProviderType = "AwsKms"`) so both S3-bound and local/EBS data are covered.
3. Ensure `EnableAtRestEncryption = true` (and typically `EnableInTransitEncryption = true`) are set so the encryption configuration is actually applied to the cluster.
4. Attach the security configuration to the `aws_emr_cluster` resource via its `security_configuration` attribute — creating the security configuration alone does not encrypt anything unless a cluster references it.
5. Grant the EMR service role and EC2 instance profile `kms:Decrypt`/`kms:GenerateDataKey` permissions on the KMS key's policy, or cluster provisioning will fail.
6. Because this check does a substring match, verify your actual EMR cluster documents/config reflect true SSE-KMS usage rather than crafting a config that merely contains the string incidentally.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EMRClusterIsEncryptedKMS.py
- AWS docs: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-encryption-enable.html
