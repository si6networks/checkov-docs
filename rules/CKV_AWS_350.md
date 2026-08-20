# CKV_AWS_350: Ensure EMR Cluster security configuration encrypts EBS disks
## Severity
**HIGH** (score: 7.5/10)

EBS volumes attached to EMR nodes hold persistent job data and can be captured via snapshots; leaving them unencrypted exposes potentially sensitive analytics data at rest to anyone who can access the underlying volume or a snapshot of it.

## Summary
Ensures an EMR security configuration that enables at-rest encryption also enables EBS volume encryption specifically, not just S3 or local-disk encryption.

## Applicability
- **Framework**: Terraform
- **Resource type**: `aws_emr_security_configuration`

## Why it matters
EMR clusters typically attach EBS volumes to their EC2 nodes for HDFS storage, YARN local storage, and application data beyond instance-store capacity. Just like local (instance-store) disks, these EBS volumes can hold sensitive intermediate data, cached datasets, logs, and job artifacts throughout the cluster's lifetime. EMR's at-rest encryption configuration lets you independently toggle EBS encryption (`EnableEbsEncryption`) as a sub-setting of local disk encryption. If it's left unset while other encryption flags are enabled, EBS volumes remain unencrypted — meaning a detached/snapshotted EBS volume, a misconfigured AMI, or access to the underlying storage layer (in edge-case scenarios such as a compromised hypervisor or an improperly sanitized snapshot shared outside the account) could expose plaintext data that the organization believed was fully covered by "at-rest encryption."

## How Checkov evaluates this
The check reads `configuration[0].EncryptionConfiguration`:
- **PASS**: `EnableAtRestEncryption` is `True` **and** the nested key path `AtRestEncryptionConfiguration/LocalDiskEncryptionConfiguration/EnableEbsEncryption` resolves to a truthy value.
- **FAIL**: `EnableAtRestEncryption` is `True` but that EBS-specific flag is missing or falsy, or the encryption block doesn't otherwise satisfy the PASS condition.
- **UNKNOWN**: the top-level `configuration` attribute is missing or not a parseable list.

## Non-compliant example
```hcl
resource "aws_emr_security_configuration" "example" {
  name = "emrsc-no-ebs-encrypt"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableAtRestEncryption = true
      AtRestEncryptionConfiguration = {
        LocalDiskEncryptionConfiguration = {
          EncryptionKeyProviderType = "AwsKms"
          AwsKmsKey                = aws_kms_key.emr.arn
          # EnableEbsEncryption not set -> EBS volumes left unencrypted
        }
      }
    }
  })
}
```

## Remediated example
```hcl
resource "aws_emr_security_configuration" "example" {
  name = "emrsc-ebs-encrypted"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableAtRestEncryption = true
      AtRestEncryptionConfiguration = {
        LocalDiskEncryptionConfiguration = {
          EncryptionKeyProviderType = "AwsKms"
          AwsKmsKey                = aws_kms_key.emr.arn
          EnableEbsEncryption      = true   # explicitly enable EBS volume encryption
        }
      }
    }
  })
}
```

## Remediation steps
1. Locate `aws_emr_security_configuration` resources with `EnableAtRestEncryption = true`.
2. Within `AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration`, set `EnableEbsEncryption = true` alongside the `EncryptionKeyProviderType`/key reference already present.
3. Because EMR security configurations are immutable, this requires creating a new resource (new `name`) and re-pointing `aws_emr_cluster.security_configuration` to it — plan a rolling cluster replacement.
4. Confirm the EMR service role has the necessary KMS grants for the key used, if a custom CMK is specified.
5. Combine with CKV_AWS_349 (local disk encryption) and in-transit encryption (CKV_AWS_351) for full EMR at-rest/in-transit coverage.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EMRClusterConfEncryptsEBS.py
- AWS docs: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-encryption-enable.html
