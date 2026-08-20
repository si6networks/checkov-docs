# CKV2_AWS_10: Ensure CloudTrail trails are integrated with CloudWatch Logs

## Severity
**LOW** (score: 2.0/10)

CloudTrail trails not forwarded to CloudWatch Logs reduce real-time visibility into API activity, hampering detection of unauthorized access or account compromise in a security-critical audit trail.

## Summary
This check ensures that AWS CloudTrail trails are configured to stream their logs into a CloudWatch Logs log group, not just S3.

## Applicability
Terraform (AWS provider). Applies to `aws_cloudtrail` resources, evaluated in connection with `aws_cloudwatch_log_group` resources.

## Why it matters
CloudTrail logs delivered only to S3 are durable but not readily queryable or alertable in near-real time — investigating an incident means downloading and grepping through S3 objects. Integrating CloudTrail with CloudWatch Logs enables real-time monitoring: CloudWatch metric filters and alarms can detect security-relevant events as they happen (e.g. root account usage, unauthorized API calls, security group changes, IAM policy changes) and trigger automated notification or remediation. Without this integration, detection of malicious or anomalous API activity is delayed to whatever cadence someone manually reviews S3-stored logs, significantly slowing incident response — this maps to AWS Foundational Security Best Practices and CIS AWS Foundations Benchmark controls around trail-to-CloudWatch integration.

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_cloudtrail` resources and requires ALL of:
1. A connection exists from the `aws_cloudtrail` resource to an `aws_cloudwatch_log_group` resource, **and**
2. The `aws_cloudtrail` resource has its `cloud_watch_logs_group_arn` attribute set.

If the trail lacks a `cloud_watch_logs_group_arn` (and the corresponding IAM role ARN needed for CloudTrail to write to CloudWatch), or is not connected to any `aws_cloudwatch_log_group`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "trail_bucket" {
  bucket = "example-cloudtrail-logs"
}

resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
  # No cloud_watch_logs_group_arn / cloud_watch_logs_role_arn configured
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "trail_bucket" {
  bucket = "example-cloudtrail-logs"
}

resource "aws_cloudwatch_log_group" "trail_log_group" {
  name              = "/aws/cloudtrail/main-trail"
  retention_in_days = 365
}

resource "aws_iam_role" "cloudtrail_cw_role" {
  name               = "cloudtrail-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

resource "aws_iam_role_policy" "cloudtrail_cw_policy" {
  name   = "cloudtrail-cw-write"
  role   = aws_iam_role.cloudtrail_cw_role.id
  policy = data.aws_iam_policy_document.cloudtrail_cw_write.json
}

resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail_log_group.arn}:*"  # <-- fixed
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw_role.arn                  # <-- fixed
}
```

## Remediation steps
1. Create an `aws_cloudwatch_log_group` to receive the trail's events.
2. Create an IAM role with a trust policy allowing `cloudtrail.amazonaws.com` to assume it, and an inline/attached policy granting `logs:CreateLogStream` and `logs:PutLogEvents` scoped to that log group.
3. Set `cloud_watch_logs_group_arn` (note the trailing `:*`) and `cloud_watch_logs_role_arn` on the `aws_cloudtrail` resource.
4. Add CloudWatch metric filters and alarms on the log group for security-relevant patterns (root usage, unauthorized API calls, IAM/network policy changes) to get real value from the integration.
5. Set an appropriate log retention (`retention_in_days`) balancing cost and compliance/investigation needs.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CloudtrailHasCloudwatch.json
