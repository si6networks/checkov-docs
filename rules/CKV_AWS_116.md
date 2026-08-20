# CKV_AWS_116: Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ)

## Severity
**LOW** (score: 2.0/10)

Lacking a Dead Letter Queue only affects reliability of failed asynchronous invocations (potential silent message loss) and has minimal direct security exploitability.

## Summary
Fails when a Lambda function does not have a Dead Letter Queue (an SQS queue or SNS topic) configured to capture failed asynchronous invocation events.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_lambda_function` resource.
- **CloudFormation/SAM**: `AWS::Lambda::Function`, `AWS::Serverless::Function`.

## Why it matters
Lambda functions invoked asynchronously (e.g. from S3 event notifications, SNS, EventBridge) are retried automatically by the Lambda service on failure, but after the retry attempts are exhausted the event is normally discarded — unless a Dead Letter Queue (or Lambda's newer "on-failure destination") is configured to capture it. Without a DLQ:
- **Silent data loss**: Events that fail all invocation attempts (due to a bug, a downstream outage, throttling, or malformed input) simply vanish, with no record for later reprocessing.
- **No failure visibility**: Operators lose the ability to alert on or investigate failed invocations at the individual-event level; they may only notice a problem once its downstream effects are user-visible.
- **Compliance/data-integrity risk**: For pipelines processing business-critical events (orders, financial transactions, audit records), losing failed events without a durable record undermines data integrity guarantees.

Configuring a DLQ (or a failure destination) ensures failed events are preserved for inspection, alerting, and reprocessing instead of being dropped.

## How Checkov evaluates this
- **Terraform**: Checks that `dead_letter_config[0].target_arn` is set to any non-empty value (`ANY_VALUE`). Fails if the `dead_letter_config` block or its `target_arn` is missing.
- **CloudFormation**: Checks `Properties/DeadLetterConfig/TargetArn` for `AWS::Lambda::Function`, or `Properties/DeadLetterQueue/TargetArn` for SAM's `AWS::Serverless::Function`. Passes if any value is present.

## Non-compliant example
```hcl
resource "aws_lambda_function" "bad" {
  function_name = "process-events"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"
  # no dead_letter_config block
}
```

## Remediated example
```hcl
resource "aws_sqs_queue" "dlq" {
  name                      = "process-events-dlq"
  message_retention_seconds = 1209600 # 14 days
}

resource "aws_lambda_function" "good" {
  function_name = "process-events"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}
```

## Remediation steps
1. Create an SQS queue (or SNS topic) to serve as the DLQ, sized/retention-tuned appropriately (e.g. 14-day message retention for SQS to allow time for investigation).
2. Add a `dead_letter_config` block referencing that queue/topic's ARN as `target_arn`.
3. Grant the Lambda execution role `sqs:SendMessage` (or `sns:Publish`) permission on the DLQ resource — this is required for the DLQ delivery to succeed and is a common oversight.
4. Consider using Lambda's newer "on-failure destination" (`aws_lambda_function_event_invoke_config` with `destination_config.on_failure`) instead of/alongside the legacy DLQ — destinations carry richer failure context (invocation payload plus error details) and also support success destinations.
5. Set up a CloudWatch alarm on the DLQ's `ApproximateNumberOfMessagesVisible` metric so failed events are actively surfaced rather than silently accumulating.
6. Note this check only applies meaningfully to asynchronously-invoked functions; functions invoked synchronously (e.g. via API Gateway/ALB) don't use DLQ the same way, but Checkov does not distinguish invocation type — you may need a suppression comment for purely synchronous functions if a DLQ genuinely doesn't apply.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaDLQConfigured.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LambdaDLQConfigured.py
- AWS documentation: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-dlq
