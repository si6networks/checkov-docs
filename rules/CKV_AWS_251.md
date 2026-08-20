# CKV_AWS_251: Ensure CloudTrail logging is enabled

## Severity
**LOW** (score: 2.0/10)

Disabling CloudTrail logging removes the account's foundational audit trail of API activity, eliminating the ability to detect or investigate unauthorized actions across the entire AWS account.

## Summary
This check ensures that an `aws_cloudtrail` resource has its `enable_logging` attribute set to `true` (or left at its default, which is also true), rather than explicitly disabled.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_cloudtrail`

## Why it matters
CloudTrail is the primary source of API-level audit records for an AWS account — every console action, CLI call, and SDK call made against AWS services is (if a trail is active) logged with the identity, source IP, and parameters of the call. A trail resource that exists in your Terraform configuration but has logging explicitly disabled (`enable_logging = false`) creates a false sense of security: the trail object is visible in the console/CLI and looks configured, but it is silently not capturing any events. This is a particularly dangerous misconfiguration because it can hide the fact that audit logging has effectively been turned off — during an incident, responders would find no CloudTrail events for the period in question, destroying the ability to reconstruct what an attacker did (which API calls they made, what resources they touched, whether they exfiltrated data) and potentially violating compliance frameworks (PCI-DSS, SOC 2, HIPAA) that mandate continuous audit logging.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` inspecting the `enable_logging` attribute, with `missing_block_result=CheckResult.PASSED` (since the Terraform provider defaults `enable_logging` to `true` when the argument is omitted entirely).

- **PASS**: `enable_logging` is unset (defaults true) or explicitly `true`.
- **FAIL**: `enable_logging = false` is explicitly set.

## Non-compliant example
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  enable_logging                = false   # logging explicitly disabled
}
```

## Remediated example
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  enable_logging                = true    # <-- explicitly enabled (or simply omit the attribute)
}
```

## Remediation steps
1. Remove `enable_logging = false` from the `aws_cloudtrail` resource, or set it explicitly to `true`.
2. Verify in the AWS Console/CLI (`aws cloudtrail get-trail-status`) that `IsLogging` is `true` after applying, since drift outside Terraform (e.g., someone manually stopping the trail via `StopLogging` API) will not be reflected until the next `terraform plan`/`apply` detects and corrects it.
3. Consider adding a CloudWatch alarm or AWS Config rule (`cloud-trail-enabled` / `cloudtrail-enabled`) as a runtime safety net so logging being stopped out-of-band is detected immediately, not just at the next Terraform run.
4. Ensure the trail also has `is_multi_region_trail = true` and log file validation enabled for complete, tamper-evident coverage.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudtrailEnableLogging.py)
- [Terraform: aws_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail)
- [AWS: Working with CloudTrail trails](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-working-with-log-files.html)
