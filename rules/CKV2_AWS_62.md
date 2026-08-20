# CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled

## Severity
**LOW** (score: 2.0/10)

Missing S3 event notifications reduces operational visibility into bucket activity but is not itself an exploitable misconfiguration and mainly aids monitoring/automation rather than closing an attack path.

## Summary
This check requires every `aws_s3_bucket` to have a connected `aws_s3_bucket_notification` resource, so that object-level events (creation, deletion, restore) trigger downstream notifications (SNS, SQS, Lambda, EventBridge).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_s3_bucket` (must be connected to `aws_s3_bucket_notification`)

## Why it matters
Without event notifications, changes to bucket contents are invisible in real time — there is no automated way to detect that an unexpected object was uploaded (e.g., malware, exfiltrated data staged for later retrieval, or a misconfigured process writing to the wrong place), that sensitive objects were deleted (potential data-destruction attack or ransomware), or to trigger automated response workflows (antivirus scanning, DLP inspection, replication, indexing). Relying solely on periodic scanning or CloudTrail data events (which many accounts don't enable due to cost) leaves a detection gap. Event notifications enable near-real-time, event-driven security and operational responses — for example, invoking a Lambda to scan every newly uploaded object, or alerting via SNS when objects appear in an bucket that should be write-only from a specific pipeline.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy):
1. Filters to `aws_s3_bucket` resources.
2. Requires a graph **connection** to exist between that bucket and an `aws_s3_bucket_notification` resource (referencing the bucket via `bucket`).

If no `aws_s3_bucket_notification` resource references the bucket, the check **FAILS**, regardless of what the notification configuration actually specifies (the check only verifies wiring exists, not that any particular event type is configured).

## Non-compliant example
```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads"
}
# No aws_s3_bucket_notification resource -> FAILS
```

## Remediated example
```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads"
}

resource "aws_sns_topic" "upload_events" {
  name = "s3-upload-events"
}

resource "aws_s3_bucket_notification" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  topic {
    topic_arn = aws_sns_topic.upload_events.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
}
```

## Remediation steps
1. Add an `aws_s3_bucket_notification` resource with `bucket` set to the target bucket's id/ARN.
2. Choose a destination appropriate to the use case: `lambda_function` for inline processing (e.g., malware scanning, thumbnail generation), `sqs_queue` for decoupled queue-based processing, `topic` (SNS) for fan-out alerting, or EventBridge (enabled via `eventbridge = true`) for flexible downstream routing without per-bucket wiring.
3. Grant the destination resource the necessary resource-based policy permitting S3 to invoke/publish to it (`aws_lambda_permission`, SNS topic policy, or SQS queue policy) — Terraform will error at apply time if this is missing.
4. Scope `events` to the specific S3 event types relevant to your monitoring/processing need rather than subscribing to everything, to avoid noise and cost.
5. Consider using EventBridge as the single S3 notification target and fanning out rules downstream — this avoids the one-destination-type-per-bucket limitations of native S3 notifications.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3BucketEventNotifications.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventNotifications.html
