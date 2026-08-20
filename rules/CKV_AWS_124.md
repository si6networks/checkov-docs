# CKV_AWS_124: Ensure that CloudFormation stacks are sending event notifications to an SNS topic

## Severity
**LOW** (score: 2.0/10)

Missing SNS notifications for CloudFormation stack events reduces operational awareness of stack changes but is not itself an exploitable access-control or encryption gap.

## Summary
Fails when an `aws_cloudformation_stack` resource does not specify any `notification_arns`, meaning stack lifecycle events are not published to an SNS topic.

## Applicability
- **Terraform**: `aws_cloudformation_stack` resource.

## Why it matters
CloudFormation stack events (resource creation/update/deletion, rollback, failure) can indicate configuration drift, unauthorized/unexpected changes, or failed deployments that leave infrastructure in an inconsistent or partially-applied state. Without event notifications routed to an SNS topic:
- Operators have no automated, real-time signal when a stack update fails, rolls back, or is deleted — they must proactively poll the CloudFormation console/API to notice problems, delaying incident detection.
- Unexpected or unauthorized stack modifications (e.g. an out-of-band change via the console by someone bypassing the normal Terraform/CI pipeline) go unnoticed until their effects surface elsewhere.
- Downstream automation (e.g. auto-remediation Lambdas, ChatOps alerts, ticketing integrations) cannot react to stack state changes if there's no event stream to subscribe to.

This is fundamentally an observability and change-detection control: routing stack events to SNS enables alerting, auditing, and automated response to infrastructure lifecycle events, closing a monitoring gap that could otherwise let failed or unauthorized changes go unnoticed.

## How Checkov evaluates this
A `BaseResourceValueCheck` using `ANY_VALUE` as the expected value for the `notification_arns` attribute:
- **PASS** if `notification_arns` is set to any non-empty value (at least one SNS topic ARN).
- **FAIL** if `notification_arns` is absent/empty.

## Non-compliant example
```hcl
resource "aws_cloudformation_stack" "bad" {
  name = "network-stack"

  template_body = jsonencode({
    Resources = {
      MyVPC = {
        Type = "AWS::EC2::VPC"
        Properties = {
          CidrBlock = "10.0.0.0/16"
        }
      }
    }
  })
  # notification_arns not set
}
```

## Remediated example
```hcl
resource "aws_sns_topic" "cfn_events" {
  name = "cloudformation-stack-events"
}

resource "aws_cloudformation_stack" "good" {
  name = "network-stack"

  template_body = jsonencode({
    Resources = {
      MyVPC = {
        Type = "AWS::EC2::VPC"
        Properties = {
          CidrBlock = "10.0.0.0/16"
        }
      }
    }
  })

  notification_arns = [aws_sns_topic.cfn_events.arn]
}
```

## Remediation steps
1. Create (or identify an existing) SNS topic dedicated to infrastructure/stack lifecycle notifications.
2. Set `notification_arns = [aws_sns_topic.<topic>.arn]` on the `aws_cloudformation_stack` resource (a list, so multiple topics can be specified for different audiences).
3. Subscribe relevant consumers to the topic: an email/Slack integration for human alerting, and/or a Lambda function for automated response (e.g. auto-rollback triggers, ticket creation).
4. Grant the CloudFormation service (or the IAM role CloudFormation assumes, if using a service role) permission to publish to the SNS topic via the topic's resource policy if cross-account, though same-account stacks typically work without extra topic policy changes.
5. Note this only applies to stacks provisioned via `aws_cloudformation_stack` directly (a comparatively uncommon pattern versus first-class Terraform resources) — if your organization primarily deploys via native Terraform resources rather than nested CloudFormation stacks, this check may have limited applicability; consider equivalent notification/alerting for your actual deployment pipeline (e.g. CI/CD job status, Terraform Cloud run notifications).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudformationStackNotificationArns.py
- AWS documentation: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-sns-notifications.html
