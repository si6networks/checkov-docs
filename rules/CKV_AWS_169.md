# CKV_AWS_169: Ensure SNS topic policy is not public by only allowing specific services or principals to access it

## Severity
**MEDIUM** (score: 5.0/10)

An SNS topic policy open to any principal allows arbitrary external accounts to publish to or subscribe on the topic, enabling spoofed notifications, message injection, or exfiltration of published data to attacker-controlled subscribers.

## Summary
This check requires that an SNS topic's resource policy does not grant unrestricted (effectively public) publish/subscribe access, by analyzing the policy for internet-accessible actions.

## Applicability
- **Terraform**: `aws_sns_topic_policy`

## Why it matters
SNS topics are often used for fan-out notification patterns (alerting, event distribution to Lambda/SQS/HTTP subscribers, mobile push). A topic policy that grants `Principal: "*"` on actions like `sns:Publish` or `sns:Subscribe` without restricting conditions allows any AWS account (or, depending on statement structure, potentially unauthenticated callers) to publish arbitrary messages into the topic or subscribe endpoints to receive its traffic.

An attacker able to publish to the topic can inject spoofed events into every downstream subscriber (e.g. triggering unintended Lambda invocations, forging alerts to cause alert fatigue or mask real incidents, or feeding malicious data into automated pipelines that trust message content). An attacker able to subscribe can exfiltrate sensitive data being broadcast through the topic (e.g. security alerts, business events, PII) to an external endpoint they control.

## How Checkov evaluates this
The check reads the `policy` attribute on `aws_sns_topic_policy`. If no policy value is present, the check **PASSES**. If the policy is present but not a literal map/object, the result is `UNKNOWN`. Otherwise, the check parses the policy with the `cloudsplaining` library's `ResourcePolicyDocument` and looks for `internet_accessible_actions`. If any exist, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_sns_topic" "alerts" {
  name = "security-alerts"
}

resource "aws_sns_topic_policy" "alerts_policy" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAll"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["sns:Publish", "sns:Subscribe"]
        Resource  = aws_sns_topic.alerts.arn
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_sns_topic" "alerts" {
  name = "security-alerts"
}

resource "aws_sns_topic_policy" "alerts_policy" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatchAlarmsOnly"
        Effect    = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:*"  # scoped condition
          }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Remove wildcard `"*"` principals from the topic policy; scope `Principal` to specific IAM roles, accounts, or AWS service principals (e.g. `cloudwatch.amazonaws.com`, `s3.amazonaws.com`) that need to publish or subscribe.
2. When allowing a service principal, add a restricting condition (`aws:SourceArn`, `aws:SourceAccount`) so only your specific resources (not any account's) can trigger the permission.
3. Scope `Action` to only what's needed (`sns:Publish` for publishers, `sns:Subscribe` for subscribers) rather than broad wildcards.
4. If no cross-account/service access is needed, remove the custom policy — SNS topics default to private, owner-account-only access.
5. This is a metadata-only change, safe to apply without recreating the topic or disrupting existing legitimate subscriptions (verify legitimate subscribers are still covered by the tightened policy before applying).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SNSTopicPolicyAnyPrincipal.py
- AWS docs: https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html
