# CKV_AWS_254: Ensure DLM cross region events are encrypted with Customer Managed Key

## Severity
**LOW** (score: 2.0/10)

The cross-region copy is already required to be encrypted by this point; using the AWS-managed default key instead of a CMK only weakens the ability to scope decrypt access and audit key usage for backup data, rather than leaving the copy unencrypted.

## Summary
This check ensures that AWS Data Lifecycle Manager (DLM) `cross_region_copy` actions are encrypted using a customer-managed KMS key (CMK), not just "encryption enabled" with the default AWS-managed key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_dlm_lifecycle_policy`

## Why it matters
This check tightens CKV_AWS_253: it's not enough for the cross-region snapshot copy to merely be encrypted — encryption with the AWS-managed default EBS key gives you no ability to control who can decrypt the copied snapshot independently of general EBS access, no separate audit trail for key usage, and no way to revoke access to the copy without affecting every other resource using the default key. A dedicated CMK for cross-region backup copies lets you scope decrypt permissions specifically to disaster-recovery/backup-restore roles, generates distinct CloudTrail `kms:Decrypt` events you can alert on, and lets you immediately cut off access to backup data (by disabling the CMK) if the destination region or restore pipeline is ever compromised — separate from cutting off access to live production volumes.

## How Checkov evaluates this
The check walks the same nested structure as CKV_AWS_253:

```
policy_details -> action[] -> cross_region_copy[] -> encryption_configuration[] -> {encryption, cmk_arn}
```

- **PASS**: `encryption_configuration.encryption == true` **and** `cmk_arn` is set (non-empty).
- **FAIL**: `encryption` is not `true`, or `cmk_arn` is missing — even if `encryption = true` is set without a `cmk_arn`.
- `UNKNOWN`: if the block structure is malformed/missing entirely.

## Non-compliant example
```hcl
resource "aws_dlm_lifecycle_policy" "example" {
  description        = "example DLM policy"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "daily-backup"
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
      }
      retain_rule {
        count = 7
      }
    }

    action {
      name = "cross-region-copy"
      cross_region_copy {
        target = "us-west-2"
        retain_rule {
          interval      = 7
          interval_unit = "DAYS"
        }
        encryption_configuration {
          encryption = true
          # cmk_arn not set -> uses AWS-managed default key
        }
      }
    }

    target_tags = { Backup = "true" }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "dlm_backup_cmk" {
  description         = "CMK for DLM cross-region backup copies"
  enable_key_rotation = true
}

resource "aws_dlm_lifecycle_policy" "example" {
  description        = "example DLM policy"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "daily-backup"
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
      }
      retain_rule {
        count = 7
      }
    }

    action {
      name = "cross-region-copy"
      cross_region_copy {
        target = "us-west-2"
        retain_rule {
          interval      = 7
          interval_unit = "DAYS"
        }
        encryption_configuration {
          encryption = true
          cmk_arn    = aws_kms_key.dlm_backup_cmk.arn   # <-- added
        }
      }
    }

    target_tags = { Backup = "true" }
  }
}
```

## Remediation steps
1. Create (or designate) a customer-managed KMS key **in the destination region** — KMS keys are regional, and the CMK for the cross-region copy must exist where the copy lands.
2. Set `cmk_arn` inside `encryption_configuration` to that key's ARN, alongside `encryption = true`.
3. Grant the DLM execution role (and any restore role) the required `kms:Decrypt`/`kms:CreateGrant` permissions on the CMK's key policy.
4. Enable key rotation on the CMK and restrict its key policy to the specific backup/DR roles that need it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DLMEventsCrossRegionEncryptionWithCMK.py)
- [Terraform: aws_dlm_lifecycle_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dlm_lifecycle_policy)
