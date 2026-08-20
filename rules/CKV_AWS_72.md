# CKV_AWS_72: Ensure SQS policy does not allow ALL (*) actions
## Severity
**LOW** (score: 2.0/10)

An SQS queue policy that permits wildcard (*) actions can let any principal read, send, or purge queue messages, enabling message tampering, denial of service, or disclosure of sensitive payloads.

## Summary
This check fails when an SQS queue policy's statement grants `Action: "*"`, i.e., permits every SQS API action rather than a specific, scoped set of actions.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_sqs_queue_policy`
- **Check type:** resource

## Why it matters
Granting `Action: "*"` on an SQS queue policy allows whoever the policy's principal resolves to (which is often itself overly broad) to perform any SQS operation on the queue — not just sending or receiving messages, but also `sqs:DeleteQueue`, `sqs:SetQueueAttributes` (which can redirect the queue's redrive/DLQ configuration or change its access policy), and `sqs:PurgeQueue` (which can silently destroy all in-flight messages). Combined with a broad principal, this can let an attacker or a misconfigured cross-account integration destroy messages, exfiltrate data flowing through the queue, or pivot to disrupt downstream consumers that depend on the queue's availability and integrity. Least-privilege queue policies that name only the specific actions a caller needs (e.g., `sqs:SendMessage`) limit blast radius if credentials are compromised.

## How Checkov evaluates this
The check (`SQSPolicy.py`) inspects the resource's `policy` argument:
- If `policy` is present and parses as a dict (i.e., it was written as an inline Terraform object/map rather than a JSON string not yet decoded to a dict — Checkov's config parsing may render it as a dict), it looks at `policy["Statement"][0]`.
- If that first statement is a dict and `statement["Action"] == "*"` (exact string match, not a list), the check **FAILS**.
- In all other cases (no `policy` key, statement not a dict, `Action` not exactly the string `"*"`, or multiple statements where only a later one has the wildcard) the check **PASSES** — note it only inspects the *first* statement in the array, so wildcard actions on subsequent statements are not caught by this check.

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
        Sid       = "AllowAllActions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:role/order-processor" }
        Action    = "*"
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
        Sid       = "AllowScopedActions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:role/order-processor" }
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.orders.arn
      }
    ]
  })
}
```

## Remediation steps
1. Replace the wildcard `Action: "*"` with an explicit list of only the SQS API actions the consuming principal actually needs (commonly `sqs:SendMessage`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes`, `sqs:ChangeMessageVisibility`).
2. Avoid granting management-plane actions (`sqs:SetQueueAttributes`, `sqs:DeleteQueue`, `sqs:PurgeQueue`, `sqs:AddPermission`) to application-level principals — reserve these for infrastructure/deployment roles.
3. Pair scoped actions with a scoped `Principal` (avoid `Principal: "*"`) to further reduce blast radius (see also CKV_AWS_70 for the analogous S3 check).
4. If the policy has multiple statements, review all of them manually — this Checkov check only inspects the first statement in the array.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SQSPolicy.py)
- [AWS SQS identity and access management](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-authentication-and-access-control.html)
