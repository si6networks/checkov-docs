# CKV_AWS_168: Ensure SQS queue policy is not public by only allowing specific services or principals to access it

## Severity
**HIGH** (score: 7.5/10)

An SQS queue policy allowing any principal lets unauthenticated or unrelated AWS accounts send, receive, or delete messages on the queue, enabling message injection, information disclosure, or denial-of-service against consuming applications.

## Summary
This check requires that an SQS queue's resource policy does not grant unrestricted (effectively public) access to send/receive/manage messages, by analyzing the policy for internet-accessible actions granted without adequate principal/condition restrictions.

## Applicability
- **Terraform**: `aws_sqs_queue` (inline `policy` attribute) and `aws_sqs_queue_policy` (standalone policy resource)

## Why it matters
An SQS queue with an overly permissive policy (e.g. `Principal: "*"` with actions like `sqs:SendMessage` or `sqs:ReceiveMessage` and no restricting conditions) can allow any AWS principal on the internet to inject arbitrary messages into the queue, read/delete messages intended for legitimate consumers, or exhaust the queue's capacity (denial of service). Because SQS is frequently used as the backbone for asynchronous processing pipelines (order processing, notification fan-out, worker queues), an attacker able to inject or drain messages can corrupt downstream business logic, cause duplicate processing, silently drop legitimate work, or use the queue to smuggle malicious payloads into internal processing systems that trust queue content.

## How Checkov evaluates this
The check reads the `policy` attribute on either `aws_sqs_queue_policy` or `aws_sqs_queue`. If no policy is set, the check **PASSES** (default SQS access is private, requiring IAM permissions on the queue owner's account). If a policy is present but not expressed as a literal map/object (e.g. it's a data-source reference Checkov cannot statically resolve), the result is `UNKNOWN`. Otherwise the check parses the policy using the `cloudsplaining` library's `ResourcePolicyDocument` and checks for `internet_accessible_actions` (actions available to an unrestricted principal). If any are found, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_sqs_queue" "orders" {
  name = "orders-queue"
}

resource "aws_sqs_queue_policy" "orders_policy" {
  queue_url = aws_sqs_queue.orders.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAll"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.orders.arn
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_sqs_queue" "orders" {
  name = "orders-queue"
}

resource "aws_sqs_queue_policy" "orders_policy" {
  queue_url = aws_sqs_queue.orders.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrderServiceOnly"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/order-service-role"  # scoped principal
        }
        Action   = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.orders.arn
      }
    ]
  })
}
```

## Remediation steps
1. Remove wildcard (`"*"`) principals from the queue policy; scope `Principal` to specific IAM role/user/account ARNs or AWS service principals (e.g. `sns.amazonaws.com` for SNS-to-SQS subscriptions) that legitimately need access.
2. If a service principal like SNS must be allowed, add a condition such as `aws:SourceArn` restricting it to a specific topic ARN, rather than allowing any account to trigger delivery.
3. Scope `Action` to the minimum operations required (e.g. `sqs:SendMessage` for publishers, `sqs:ReceiveMessage`/`sqs:DeleteMessage` for consumers) instead of `sqs:*`.
4. If no cross-account/service access is required, remove the policy entirely and rely on IAM identity-based policies for access control — SQS defaults to private within the owning account.
5. This is a metadata-only change (the policy document), safe to apply without downtime or queue recreation.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SQSQueuePolicyAnyPrincipal.py
- AWS docs: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html
