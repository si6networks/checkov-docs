# CKV_AWS_255: Ensure DLM cross region schedules are encrypted

## Severity
**LOW** (score: 2.0/10)

DLM schedule-based cross-region copy rules that omit the encrypted flag can produce unencrypted snapshot replicas of volume data in the destination region, the same at-rest exposure risk as the action-based variant.

## Summary
This check ensures that AWS Data Lifecycle Manager (DLM) `schedule` blocks with a `cross_region_copy_rule` have encryption enabled for the resulting cross-region snapshot copies.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_dlm_lifecycle_policy`

## Why it matters
DLM's `schedule` block is an alternative (newer) way of defining cross-region snapshot copy behavior via `cross_region_copy_rule`, distinct from the `action`-level `cross_region_copy` block covered by CKV_AWS_253/254 but with the same underlying risk: if the `encrypted` flag isn't set on the copy rule, the resulting snapshot copy in the target region may be unencrypted even if the source is encrypted. An unencrypted cross-region snapshot copy is a full, at-rest replica of your volume's data sitting in a second region without the protections you assumed applied — readable by anyone with sufficient IAM/snapshot-sharing access there, and outside the audit/access boundary the source encryption key provides.

## How Checkov evaluates this
The check walks:

```
policy_details -> schedule[] -> cross_region_copy_rule[] -> encrypted
```

- For each `schedule`, iterates every `cross_region_copy_rule`.
- **FAIL**: as soon as any rule has `encrypted != [True]` (i.e., not explicitly `true`).
- **PASS**: only if *all* `cross_region_copy_rule` entries within a schedule have `encrypted = true`.
- If there's no `schedule` block, or no `cross_region_copy_rule` within it, the result is `UNKNOWN` (not evaluated).

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
        # encrypted not set -> defaults to unencrypted copy
        copy_tags = true
      }
    }

    target_tags = { Backup = "true" }
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

      cross_region_copy_rule {
        target    = "us-west-2"
        encrypted = true   # <-- added
        copy_tags = true
      }
    }

    target_tags = { Backup = "true" }
  }
}
```

## Remediation steps
1. Locate every `cross_region_copy_rule` block nested under `schedule` in your `aws_dlm_lifecycle_policy` resources.
2. Add `encrypted = true` to each one.
3. For stronger control, also set `cmk_arn` to use a customer-managed key rather than the AWS-managed default (see CKV_AWS_256).
4. This is a policy-configuration-only change — it affects future snapshot copies, not retroactively re-encrypting existing copies, so no resource downtime is involved.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DLMScheduleCrossRegionEncryption.py)
- [Terraform: aws_dlm_lifecycle_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dlm_lifecycle_policy)
- [AWS: Amazon Data Lifecycle Manager](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-lifecycle.html)
