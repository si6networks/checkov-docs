# CKV_AWS_253: Ensure DLM cross region events are encrypted

## Severity
**LOW** (score: 2.0/10)

EBS snapshots cross-region-copied by a DLM action without requesting encryption can land as unencrypted, full at-rest replicas of volume data in a second region, defeating the source volume's encryption protections.

## Summary
This check ensures that AWS Data Lifecycle Manager (DLM) policies which copy snapshots to another region (`cross_region_copy` actions) encrypt the copied snapshots.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_dlm_lifecycle_policy`

## Why it matters
DLM lifecycle policies automate EBS snapshot management, and their `cross_region_copy` action replicates snapshots to a secondary region for disaster recovery. If the source volume/snapshot is encrypted but the cross-region copy action doesn't explicitly request encryption, the copy can end up as an unencrypted snapshot in the destination region — silently defeating the encryption guarantees you established on the source. An unencrypted snapshot copy is a full at-rest copy of your volume's data (potentially including credentials, PII, or other sensitive application state baked into disk images) sitting in a second region, readable to anyone with snapshot-sharing/describe permissions there, and outside whatever CMK-based access controls protect the original.

## How Checkov evaluates this
The check walks the nested Terraform block structure of `aws_dlm_lifecycle_policy`:

```
policy_details -> action[] -> cross_region_copy[] -> encryption_configuration[] -> encryption
```

- For each `action` block, if it contains a `cross_region_copy` block:
  - **PASS**: if `encryption_configuration.encryption == true`.
  - **FAIL**: otherwise (missing `encryption_configuration`, or `encryption` set to `false`/absent).
- If the structure can't be parsed as expected (missing/malformed blocks), the result is `UNKNOWN`.
- If there is no `cross_region_copy` action at all, the result is `UNKNOWN` (not evaluated) rather than PASS, since this check is specifically about cross-region copy encryption, not a general policy requirement.

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
        # encryption_configuration missing -> copy is unencrypted
      }
    }

    target_tags = {
      Backup = "true"
    }
  }
}
```

## Remediated example
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
          encryption = true   # <-- added
        }
      }
    }

    target_tags = {
      Backup = "true"
    }
  }
}
```

## Remediation steps
1. Add an `encryption_configuration` block inside every `cross_region_copy` block within an `action`.
2. Set `encryption = true`.
3. Consider going further and pinning a specific customer-managed key via `cmk_arn` (see CKV_AWS_254) rather than relying on the AWS-managed default key.
4. Apply — this affects only future snapshot copies made by the policy, not existing copies, so no downtime is involved.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DLMEventsCrossRegionEncryption.py)
- [Terraform: aws_dlm_lifecycle_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dlm_lifecycle_policy)
- [AWS: Amazon Data Lifecycle Manager](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-lifecycle.html)
