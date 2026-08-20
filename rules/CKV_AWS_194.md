# CKV_AWS_194: Ensure AppSync has Field-Level logs enabled
## Severity
**LOW** (score: 2.0/10)

Field-level logging adds finer-grained request/response detail on top of basic AppSync logging, so its absence reduces investigative detail during an incident rather than removing monitoring capability entirely.

## Summary
This check requires that an AWS AppSync GraphQL API's logging configuration sets `FieldLogLevel`/`field_log_level` to either `ALL` or `ERROR`, so resolver-level execution details (not just top-level request logs) are captured.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource/entity types:** `AWS::AppSync::GraphQLApi` (CloudFormation); `aws_appsync_graphql_api` (Terraform)
- **Check type:** resource (attribute-value check)

## Why it matters
AppSync GraphQL queries can invoke many resolvers per request (one per requested field/nested type), each potentially calling a different backend (DynamoDB table, Lambda function, HTTP data source). Basic API-level logging alone shows that a request happened, but not which individual field resolvers were invoked, what data sources they touched, what errors they threw, or how long each took. Setting `field_log_level` to `NONE` (or leaving the default) means resolver-level errors — including authorization failures at the field level, injection attempts against resolver arguments, or misconfigured VTL/JS resolver logic — go completely unlogged. This is a significant gap for APIs enforcing field-level authorization (e.g., `@aws_auth` directives or fine-grained resolver logic), since without field-level logs you cannot verify after the fact whether an authorization bypass or data leak occurred through a specific field resolver.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` subclasses using `get_expected_values` (a list) instead of a single expected value:
- **CloudFormation:** inspects `Properties/LogConfig/FieldLogLevel`; passes only if the value is `"ALL"` or `"ERROR"`.
- **Terraform:** inspects `log_config/[0]/field_log_level`; same two accepted values.

If the field is absent, set to `"NONE"`, or any other value, the check FAILS.

## Non-compliant example
```hcl
resource "aws_appsync_graphql_api" "example" {
  name                = "app-api"
  authentication_type = "API_KEY"
  schema              = file("${path.module}/schema.graphql")

  log_config {
    cloudwatch_logs_role_arn = aws_iam_role.appsync_logging.arn
    field_log_level          = "NONE"  # or omitted entirely
  }
}
```

## Remediated example
```hcl
resource "aws_appsync_graphql_api" "example" {
  name                = "app-api"
  authentication_type = "API_KEY"
  schema              = file("${path.module}/schema.graphql")

  log_config {
    cloudwatch_logs_role_arn = aws_iam_role.appsync_logging.arn
    field_log_level          = "ERROR"  # or "ALL" for full resolver-level detail
  }
}
```

## Remediation steps
1. Ensure the AppSync API already has CloudWatch logging enabled (see CKV_AWS_193 for the `cloudwatch_logs_role_arn` prerequisite).
2. Set `field_log_level`/`FieldLogLevel` to `"ERROR"` at minimum (logs resolver errors only) or `"ALL"` for full detail including successful resolver invocations and request/response mapping — `ALL` is more useful for security investigations and debugging but generates significantly more log volume/cost.
3. If using `ALL`, review CloudWatch Logs retention settings and cost, and consider filtering/exporting logs to a SIEM for longer-term retention and correlation with other application logs.
4. Be aware `ALL`-level logs may include request/response payload data — apply appropriate CloudWatch Logs access controls and encryption if the GraphQL payloads contain sensitive fields.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/AppSyncFieldLevelLogs.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AppSyncFieldLevelLogs.py)
- [AWS AppSync logging configuration documentation](https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html)
