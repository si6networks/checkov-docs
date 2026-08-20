# CKV_AWS_67: Ensure CloudTrail is enabled in all Regions
## Severity
**LOW** (score: 2.0/10)

A CloudTrail not enabled across all regions leaves API activity in non-configured regions unlogged, creating a blind spot that attackers can exploit to operate undetected and hindering incident response and forensics.

## Summary
This check verifies that a CloudTrail trail has `IsMultiRegionTrail`/`is_multi_region_trail` set to `true`, so that API activity is logged across all AWS regions rather than only the region where the trail was created.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::CloudTrail::Trail`, property `Properties/IsMultiRegionTrail`.
- **Terraform**: `aws_cloudtrail` resource, attribute `is_multi_region_trail`.

## Why it matters
By default, a CloudTrail trail only records events for the single AWS region it was created in. Because most AWS APIs are region-scoped, an attacker with compromised credentials can simply operate in a region your organization isn't actively monitoring (e.g., spinning up resources in `ap-southeast-2` when your security team only reviews `us-east-1` logs) and their activity goes completely unrecorded. This "blind region" pattern is a well-known technique for evading detection after initial account compromise. A multi-region trail closes this gap by capturing management-event API calls consistently across every region, including regions you don't normally use, ensuring a single, complete audit trail for incident response, forensic investigation, and compliance requirements (e.g., CIS AWS Foundations Benchmark explicitly requires multi-region CloudTrail).

## How Checkov evaluates this
Both are `BaseResourceValueCheck` implementations:
- **CloudFormation**: inspects `Properties/IsMultiRegionTrail`.
- **Terraform**: inspects `is_multi_region_trail`.
- PASS: value is `true`.
- FAIL: value is `false`, or the attribute is absent (Terraform's `aws_cloudtrail` default for `is_multi_region_trail` is `false` if unset).

## Non-compliant example
```hcl
resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = false   # non-compliant
  include_global_service_events = true
}
```

## Remediated example
```hcl
resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true    # fixed
  include_global_service_events = true
  enable_log_file_validation     = true
}
```

## Remediation steps
1. Set `is_multi_region_trail = true` (Terraform) or `IsMultiRegionTrail: true` (CloudFormation) on the trail resource.
2. Keep `include_global_service_events = true` so global service events (IAM, STS, CloudFront, Route 53) are captured alongside regional events.
3. Also enable `enable_log_file_validation` for log integrity verification, and consider `enable_logging = true` explicitly (some tooling has shipped trails that are created but not actively logging).
4. If managing multiple accounts, use AWS Organizations trails (an org-wide multi-region trail configured in the management account) to centralize logging across the entire organization rather than configuring per-account trails individually.
5. This is a non-disruptive, in-place configuration change; no downtime or replacement required.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudtrailMultiRegion.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudtrailMultiRegion.py)
- [AWS: Enabling CloudTrail in all Regions](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-supported-regions.html)
