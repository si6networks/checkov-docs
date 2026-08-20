# CKV_AWS_349: Ensure EMR Cluster security configuration encrypts local disks
## Severity
**LOW** (score: 2.0/10)

Unencrypted local (instance-store) disks on EMR cluster nodes can expose intermediate/spill data processed during big-data jobs to anyone with access to the underlying host or its disk snapshots.

## Summary
Ensures an EMR security configuration that enables at-rest encryption also enables local disk encryption specifically, rather than leaving instance store/local volumes unencrypted.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource type**: `aws_emr_security_configuration`

## Why it matters
Amazon EMR clusters write intermediate MapReduce/Spark shuffle data, spill files, cached datasets, and temporary job artifacts to local (instance store or attached) disks during processing — data that can include the same sensitive records being processed even if the "final" output in S3 is encrypted. EMR's at-rest encryption setting has two independently-configurable scopes: EBS volume encryption and local disk encryption (via LUKS). Enabling `EnableAtRestEncryption` without also configuring `LocalDiskEncryptionConfiguration` leaves local ephemeral storage in plaintext. If an instance is compromised, decommissioned without secure wipe, or its underlying physical disk is later repurposed/inspected (in on-prem-adjacent or forensic scenarios), sensitive intermediate data could be recovered from that local disk even though the cluster's "encryption" flag was nominally turned on — a subtle gap that gives a false sense of complete encryption coverage.

## How Checkov evaluates this
The check reads the `configuration[0]` block and looks specifically for `EncryptionConfiguration`:
- If `EncryptionConfiguration.EnableAtRestEncryption` is **not** `True`, the check still proceeds to the general fallthrough — since the only path to PASS requires `EnableAtRestEncryption == True` **and** a local disk key present, any configuration without that combination returns **FAIL**.
- **PASS**: `EnableAtRestEncryption` is `True` **and** the key path `AtRestEncryptionConfiguration/LocalDiskEncryptionConfiguration` is present and non-empty inside the encryption config (found via a recursive dict search).
- **FAIL**: `EnableAtRestEncryption` is `True` but `LocalDiskEncryptionConfiguration` is missing/empty, or the whole `configuration` block exists without meeting the above.
- **UNKNOWN**: the `configuration` attribute itself is missing or not a list (Checkov can't parse it, e.g. because it's a computed/external JSON string it can't statically evaluate).

## Non-compliant example
```hcl
resource "aws_emr_security_configuration" "example" {
  name = "emrsc-no-local-disk"

  configuration = jsonencode({
    EncryptionConfiguration = {
      EnableInTransitEncryption = true
      EnableAtRestEncryption    = true
      AtRestEncryptionConfiguration = {
        S3EncryptionConfiguration = {
          EncryptionMode = "SSE-S3"
        }
        # LocalDiskEncryptionConfiguration missing -> local disks stay unencrypted
      }
    }
  })
}
```

## Remediated example
```hcl
resource "aws_emr_security_configuration" "example" {
  name = "emrsc-local-disk-encrypted"

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
          AwsKmsKey                = aws_kms_key.emr.arn
        }
      }
    }
  })
}

resource "aws_kms_key" "emr" {
  description             = "CMK for EMR local disk encryption"
  deletion_window_in_days = 30
}
```

## Remediation steps
1. Locate every `aws_emr_security_configuration` resource where `EnableAtRestEncryption` is set to `true`.
2. Add an `AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration` block specifying an `EncryptionKeyProviderType` (`AwsKms` recommended) and corresponding key reference.
3. Attach this security configuration to your EMR clusters via the `security_configuration` argument on `aws_emr_cluster`.
4. Note: EMR security configurations are immutable once created — changing the JSON requires creating a new `aws_emr_security_configuration` resource (new name) and pointing clusters to it; it cannot be updated in place.
5. Verify instance types used support local disk encryption (most current-generation instance families do); confirm no performance regression for shuffle-heavy workloads, as LUKS encryption adds CPU overhead.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EMRClusterConfEncryptsLocalDisk.py
- AWS docs: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-encryption-enable.html
