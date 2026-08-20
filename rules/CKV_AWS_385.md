# CKV_AWS_385: Ensure AWS SNS topic policies do not allow cross-account access

## Severity
**HIGH** (score: 7.0/10)

An SNS topic policy that permits cross-account access without tight principal restriction allows other AWS accounts to publish to or subscribe on the topic, risking unauthorized message injection or interception of sensitive notifications.

## Summary
This check flags an SNS topic policy that grants `Allow` permissions to a specific external AWS account (a full IAM ARN principal) without any accompanying `Condition` clause to restrict that grant.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_sns_topic_policy`

## Why it matters
SNS topic policies control which AWS principals can publish to or subscribe from a topic. Granting a specific external account's IAM ARN as a `Principal` with an unconditioned `Allow` statement means:

- That external account (which is not your own and outside your organization's direct control) can perform the granted actions (e.g., `sns:Publish`, `sns:Subscribe`) with no further restriction — no source IP, VPC endpoint, source ARN, or MFA condition constraining it.
- If that external account's credentials are ever compromised, or if the account owner is later acquired/repurposed/malicious, the grant remains fully exploitable exactly as broadly as originally written.
- Best practice for any cross-account trust relationship is to always pair it with a `Condition` (e.g., `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID`) so the grant is scoped as tightly as possible and does not become a standing, unconditional trust relationship that's easy to overlook during a security review.

Note that this check does not flag wildcard (`*`) principals — those are covered by other, more specific checks (SNS public policy checks). This one specifically targets cross-account grants to a named external account ARN lacking a condition.

## How Checkov evaluates this
The check parses the `policy` attribute of `aws_sns_topic_policy` (using `cloudsplaining`'s `ResourcePolicyDocument` parser) and, for each statement:

1. Skips statements where `Effect` is not `Allow`.
2. Extracts all `Principal.AWS` values (whether a single string or a list).
3. For each principal string, checks whether it starts with `arn:aws:iam::` and is not the literal wildcard `"*"` — i.e., it identifies a **specific** IAM ARN principal (which implies cross-account access if that ARN belongs to another account).
4. If such a specific ARN principal is found on an `Allow` statement, and that statement has **no** `Condition` block at all, the check **FAILS**.
5. If the `policy` is not a dict Checkov can parse cleanly, the result is **UNKNOWN**. If there's no `policy` attribute, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_sns_topic" "example" {
  name = "example-topic"
}

resource "aws_sns_topic_policy" "example" {
  arn = aws_sns_topic.example.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::999999999999:root" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.example.arn
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_sns_topic" "example" {
  name = "example-topic"
}

resource "aws_sns_topic_policy" "example" {
  arn = aws_sns_topic.example.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::999999999999:root" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.example.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "999999999999"
          }
        }
      }
    ]
  })
}
```

## Remediation steps
1. For any statement that grants `Allow` to a specific external account's IAM ARN, add a `Condition` block that scopes the grant — e.g., `aws:SourceArn`, `aws:SourceAccount`, or `aws:PrincipalOrgID` — so the trust is not unconditionally standing open.
2. Reassess whether the cross-account grant is still needed at all; remove it if the external integration has been decommissioned.
3. Prefer resource-based conditions tied to a specific resource (e.g., a specific external SQS queue or Lambda subscribing to the topic) rather than a broad account-root principal.
4. Document the business justification for any remaining cross-account trust relationship so it can be reviewed periodically.
5. This is a policy-document change; it applies without needing to replace the SNS topic itself.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SNSCrossAccountAccess.py)
- [AWS SNS access control documentation](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html)
