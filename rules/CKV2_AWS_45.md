# CKV2_AWS_45: Ensure AWS Config recorder is enabled to record all supported resources
## Severity
**LOW** (score: 2.0/10)

A disabled or partially-scoped AWS Config recorder removes the account's ability to detect and audit configuration drift across resources, weakening detective controls without directly enabling an attack.

## Summary
This check fails when an AWS Config configuration recorder either isn't actually turned on (`aws_config_configuration_recorder_status.is_enabled` isn't `true`) or is scoped to record only a subset of resource types instead of all supported resource types (`recording_group.all_supported` is `false`).

## Applicability
- **IaC framework:** Terraform
- **Resource/entity types:** `aws_config_configuration_recorder`, `aws_config_configuration_recorder_status`

## Why it matters
AWS Config is the primary AWS-native source of configuration-change history and drift detection used for compliance auditing, incident forensics, and automated remediation triggers. If the recorder exists but is disabled, or is defined but scoped to only a handful of resource types, you get a false sense of security: dashboards, Config rules, and compliance reports will appear to be evaluating your environment while silently missing entire categories of resources (e.g. IAM changes, security group modifications, S3 bucket policy changes) that were never recorded. During an incident, an investigator relying on Config's configuration history to determine "what changed and when" will hit gaps exactly where they're needed most — precisely the resource types an attacker is likely to touch (IAM roles, security groups, KMS keys). A recorder that exists but isn't enabled, or isn't set to all-supported, provides compliance theater rather than actual coverage.

## How Checkov evaluates this
This is a graph-based JSON policy requiring several conditions together (`and`):
1. There must be an `aws_config_configuration_recorder_status` resource present.
2. That status resource must be connected (graph connection) to an `aws_config_configuration_recorder`.
3. The recorder's `recording_group.all_supported` attribute must **not** be `"false"` (i.e., it must be true or simply unset/default, which AWS treats as recording all supported types).
4. The status resource's `is_enabled` attribute must equal `"true"`.
- **FAIL** if the recorder status resource is missing/unconnected, if `all_supported` is explicitly `false`, or if `is_enabled` isn't `true`.
- **PASS** only when a connected, enabled recorder is scoped to all supported resource types.

## Non-compliant example
```hcl
resource "aws_config_configuration_recorder" "bad" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = false
    resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_configuration_recorder_status" "bad" {
  name       = aws_config_configuration_recorder.bad.name
  is_enabled = false
}
```

## Remediated example
```hcl
resource "aws_config_configuration_recorder" "good" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_configuration_recorder_status" "good" {
  name       = aws_config_configuration_recorder.good.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.good]
}

resource "aws_config_delivery_channel" "good" {
  name           = "config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_logs.bucket
}
```

## Remediation steps
1. Set `recording_group.all_supported = true` on the `aws_config_configuration_recorder` (remove any explicit `resource_types` restriction, since that's mutually exclusive with `all_supported`).
2. Add an `aws_config_configuration_recorder_status` resource referencing the recorder's `name`, with `is_enabled = true`.
3. Ensure an `aws_config_delivery_channel` exists and is created before the recorder status is enabled (Config requires a delivery channel before it can start recording) — use `depends_on` to sequence this correctly.
4. Confirm the IAM role used by Config (`role_arn`) has the `AWS_ConfigRole` managed policy or equivalent permissions to describe all supported resource types.
5. Only one configuration recorder is allowed per region/account — if one already exists, update it in place rather than creating a duplicate.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AWSConfigRecorderEnabled.json
- AWS docs: https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html
