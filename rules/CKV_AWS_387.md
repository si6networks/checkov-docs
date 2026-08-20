# CKV_AWS_387: Ensure SQS policy does not allow public access through wildcards

## Severity
**LOW** (score: 2.0/10)

An SQS queue policy allowing a wildcard principal without a restricting condition lets any AWS account or unauthenticated caller send, receive, or delete messages, enabling denial of service, data interception, or malicious payload injection into the queue.

## Summary
This check flags an SQS queue policy that grants `Allow` on SQS actions to a wildcard principal (`Principal = "*"` or `Principal.AWS = "*"`) without a `Condition` clause restricting who can actually invoke it.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_sqs_queue_policy`

## Why it matters
An SQS queue policy statement that allows `sqs:*` (or any `sqs:`/`SQS:` prefixed action) to principal `*` with no condition means **any AWS account, or even unauthenticated callers depending on the action**, can send messages to, read from, or manage the queue. This creates serious risks:

- An attacker can flood the queue with junk/malicious messages (denial of service against consumers, or a vector to inject malicious payloads that downstream consumers process unsafely).
- An attacker can read (`ReceiveMessage`) and delete messages from the queue, intercepting or destroying legitimate application data in transit between producer and consumer.
- If the queue policy also allows `SetQueueAttributes` or similar management actions, an attacker could reconfigure the queue's redrive policy, encryption settings, or access policy itself.

A `Condition` clause (e.g., `aws:SourceArn`, `aws:SourceAccount`, VPC endpoint conditions) is what normally scopes an otherwise-necessary wildcard principal (such as allowing an S3 bucket or SNS topic in the same account to publish) down to only the intended source — without it, the wildcard principal is unrestricted.

## How Checkov evaluates this
For each statement in the queue policy:

1. Skip if `Effect` is not `Allow`.
2. Determine whether the statement's `Action` includes an SQS-related action — either exactly `*`, or any action starting with `sqs:`/`SQS:`. If not, skip this statement.
3. Inspect `Principal`:
   - If `Principal` is the literal string `"*"` → check for `Condition`; if absent, **FAIL**.
   - If `Principal` is a dict with an `AWS` key equal to `"*"` (string) or containing `"*"` in a list → check for `Condition`; if absent, **FAIL**.
4. If no failing statement is found across the whole policy, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_sqs_queue" "example" {
  name = "example-queue"
}

resource "aws_sqs_queue_policy" "example" {
  queue_url = aws_sqs_queue.example.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.example.arn
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_sqs_queue" "example" {
  name = "example-queue"
}

resource "aws_sqs_queue_policy" "example" {
  queue_url = aws_sqs_queue.example.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.example.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.example.arn
          }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Replace broad wildcard `Action = "sqs:*"` with the specific action(s) actually required (e.g., `sqs:SendMessage`).
2. Add a `Condition` block scoping the wildcard `Principal` to the intended source — most commonly `aws:SourceArn` (for an S3 bucket/SNS topic in the same account allowed to publish to the queue) or `aws:SourceAccount`.
3. Where the sender is a specific IAM role/account rather than another AWS service, replace the wildcard principal entirely with the specific ARN instead of relying on a condition.
4. Verify the change against real producers (e.g., S3 event notifications, SNS subscriptions) that currently rely on the wildcard principal, since removing/conditioning it incorrectly can silently break message delivery.
5. This is a queue-policy change; it applies without needing to recreate the queue itself.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SQSOverlyPermissive.py)
- [AWS SQS identity and access management documentation](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-authentication-and-access-control.html)
