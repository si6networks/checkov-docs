# CKV_AWS_256: Ensure DLM cross region schedules are encrypted using a Customer Managed Key

## Severity
**LOW** (score: 2.0/10)

As with the action-based equivalent, the copy is already encrypted here; lacking a dedicated CMK mainly reduces the ability to independently scope and revoke decrypt access to backup data, a narrower control-hardening gap rather than an unencrypted-data exposure.

## Summary
This check ensures that AWS Data Lifecycle Manager (DLM) `schedule`-level `cross_region_copy_rule` blocks are both encrypted and use a customer-managed KMS key (CMK), rather than the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_dlm_lifecycle_policy`

## Why it matters
This check extends CKV_AWS_255: enabling encryption alone on a cross-region copy rule doesn't give you control over *who* can decrypt that copy — the default AWS-managed EBS key applies broad account-level decrypt permissions rather than a scoped policy. For backup data specifically, which is a common target in ransomware and data-exfiltration scenarios (attackers often go after backups precisely because they're less monitored than production and may contain a full historical copy of sensitive data even after production data is remediated or deleted), a dedicated CMK lets you: restrict decrypt access to only the specific DR/restore roles that need it; generate a distinct, alertable CloudTrail trail of every decrypt attempt against backup data; and immediately revoke access to backup copies (by disabling the CMK) independent of the encryption key used for live production volumes.

## How Checkov evaluates this
The check walks:

```
policy_details -> schedule[] -> cross_region_copy_rule[] -> {encrypted, cmk_arn}
```

- For each `cross_region_copy_rule`, **FAIL** is returned as soon as either:
  - `encrypted != [True]`, **or**
  - `cmk_arn` is not set (falsy).
- **PASS**: only if every `cross_region_copy_rule` within a schedule has both `encrypted = true` and a non-empty `cmk_arn`.
- `UNKNOWN`: if there's no `schedule`/`cross_region_copy_rule` structure to evaluate.

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

      cross_region_copy_rule {
        target    = "us-west-2"
        encrypted = true
        # cmk_arn not set -> uses AWS-managed default key
      }
    }

    target_tags = { Backup = "true" }
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "dlm_backup_cmk" {
  description         = "CMK for DLM cross-region schedule copies"
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

      cross_region_copy_rule {
        target    = "us-west-2"
        encrypted = true
        cmk_arn   = aws_kms_key.dlm_backup_cmk.arn   # <-- added
      }
    }

    target_tags = { Backup = "true" }
  }
}
```

## Remediation steps
1. Create (or designate) a customer-managed KMS key in the **destination region** of the cross-region copy (KMS keys are region-scoped).
2. Add both `encrypted = true` and `cmk_arn = <cmk-arn>` to every `cross_region_copy_rule` under `schedule`.
3. Update the CMK's key policy to grant the DLM service and any restore/DR IAM roles the necessary `kms:Decrypt`/`kms:CreateGrant` permissions.
4. Enable automatic key rotation on the CMK and restrict access to backup/DR-specific principals only.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DLMScheduleCrossRegionEncryptionWithCMK.py)
- [Terraform: aws_dlm_lifecycle_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dlm_lifecycle_policy)
