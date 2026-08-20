# CKV_AWS_252: Ensure CloudTrail defines an SNS Topic

## Severity
**LOW** (score: 2.0/10)

Missing an SNS topic on a CloudTrail trail delays real-time awareness of new log deliveries but does not affect whether the audit logs themselves are captured, making this an alerting-timeliness gap rather than a loss of the audit trail itself.

## Summary
This check ensures that an `aws_cloudtrail` resource specifies an SNS topic (`sns_topic_name`) so that notifications are published each time CloudTrail delivers a new log file.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_cloudtrail`

## Why it matters
By default, CloudTrail delivers log files to S3 roughly every 5 minutes with no active notification — consumers (SIEM pipelines, log-processing Lambdas, security teams) have to poll the bucket to discover new files, which introduces detection latency and creates a risk that a delivery interruption goes unnoticed. Configuring an SNS topic lets downstream systems (e.g., an SQS queue feeding a log-processing pipeline, or a Lambda that ships events to a SIEM) react to new log files in near real time, which materially shortens the mean time to detect (MTTD) suspicious activity captured in the trail. Without it, teams typically fall back to batch/scheduled ingestion, meaning a malicious action performed via the API might not be surfaced to analysts for tens of minutes or hours depending on the polling cadence — a meaningful gap during an active incident.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` inspecting the `sns_topic_name` attribute, expected value `ANY_VALUE`.

- **PASS**: `sns_topic_name` is set to any non-empty value.
- **FAIL**: `sns_topic_name` is absent/unset.

## Non-compliant example
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  # sns_topic_name not configured -> no notification on new log delivery
}
```

## Remediated example
```hcl
resource "aws_sns_topic" "cloudtrail_notifications" {
  name = "cloudtrail-log-delivery"
}

resource "aws_sns_topic_policy" "cloudtrail_notifications" {
  arn = aws_sns_topic.cloudtrail_notifications.arn

  policy = data.aws_iam_policy_document.cloudtrail_sns_policy.json
}

resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  sns_topic_name                = aws_sns_topic.cloudtrail_notifications.name   # <-- added
}
```

## Remediation steps
1. Create an SNS topic dedicated to CloudTrail log-delivery notifications.
2. Attach a resource policy to the topic allowing `cloudtrail.amazonaws.com` to publish to it (CloudTrail requires an explicit SNS topic policy granting `SNS:Publish`).
3. Set `sns_topic_name` on the `aws_cloudtrail` resource to the topic's name.
4. Subscribe an SQS queue (recommended over direct email/SMS to avoid notification flooding, per AWS guidance) or a Lambda function to the topic to drive automated log processing.
5. Monitor the subscription for delivery failures/DLQ buildup so the notification pipeline itself doesn't silently fail.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudtrailDefinesSNSTopic.py)
- [Terraform: aws_cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail)
- [AWS: Configuring Amazon SNS notifications for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html)
