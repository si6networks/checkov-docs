# CKV_AWS_193: Ensure AppSync has Logging enabled
## Severity
**LOW** (score: 2.0/10)

Missing CloudWatch logging on an AppSync GraphQL API removes the audit trail needed to detect abuse, unauthorized queries, or data exfiltration attempts against the API, a genuinely security-relevant monitoring gap.

## Summary
This check requires that an AWS AppSync GraphQL API has CloudWatch logging configured by specifying a `CloudWatchLogsRoleArn` (CloudFormation) / `cloudwatch_logs_role_arn` (Terraform) in its logging configuration.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource/entity types:** `AWS::AppSync::GraphQLApi` (CloudFormation); `aws_appsync_graphql_api` (Terraform)
- **Check type:** resource (attribute-value check)

## Why it matters
AWS AppSync is a managed GraphQL service often exposed as a public or partner-facing API endpoint. Without logging enabled, there is no CloudWatch record of incoming GraphQL requests, resolver execution, errors, or performance data — meaning your team has no visibility into abnormal query patterns (e.g., overly broad/nested queries used for data scraping or denial-of-service via query complexity attacks), authentication/authorization failures, or resolver errors indicating a bug or an attempted exploit. In an incident response scenario, an AppSync API with logging disabled leaves defenders unable to reconstruct which queries were executed, by whom, or when — a significant blind spot for an API layer that often sits directly in front of sensitive backend data sources (DynamoDB, Lambda, RDS via resolvers).

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` subclasses expecting `ANY_VALUE`:
- **CloudFormation:** inspects `Properties/LogConfig/CloudWatchLogsRoleArn`. Presence of any value passes; absence fails.
- **Terraform:** inspects `log_config/[0]/cloudwatch_logs_role_arn`. Same logic — if the `log_config` block is missing entirely, or present without `cloudwatch_logs_role_arn`, the check FAILS.

## Non-compliant example
```hcl
resource "aws_appsync_graphql_api" "example" {
  name                = "app-api"
  authentication_type = "API_KEY"
  schema              = file("${path.module}/schema.graphql")
  # log_config block not set -- no CloudWatch logging
}
```

## Remediated example
```hcl
resource "aws_iam_role" "appsync_logging" {
  name = "appsync-logging-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "appsync.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "appsync_logging" {
  role       = aws_iam_role.appsync_logging.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSAppSyncPushToCloudWatchLogs"
}

resource "aws_appsync_graphql_api" "example" {
  name                = "app-api"
  authentication_type = "API_KEY"
  schema              = file("${path.module}/schema.graphql")

  log_config {
    cloudwatch_logs_role_arn = aws_iam_role.appsync_logging.arn
    field_log_level          = "ERROR"
  }
}
```

## Remediation steps
1. Create an IAM role that AppSync can assume, with the `AWSAppSyncPushToCloudWatchLogs` managed policy (or an equivalent custom policy granting `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`).
2. Add a `log_config`/`LogConfig` block to the AppSync API resource, setting `cloudwatch_logs_role_arn`/`CloudWatchLogsRoleArn` to that role's ARN.
3. Set an appropriate `field_log_level`/`FieldLogLevel` (see CKV_AWS_194 for guidance on `ALL` vs `ERROR`).
4. Set up CloudWatch Logs retention and alerting/metric filters on the resulting log group to detect anomalous query volume or repeated authorization failures.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/AppSyncLogging.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AppSyncLogging.py)
- [AWS AppSync monitoring and logging documentation](https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html)
