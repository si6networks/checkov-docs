# CKV_AWS_76: Ensure API Gateway has Access Logging enabled
## Severity
**LOW** (score: 2.0/10)

Without API Gateway access logging, there is no record of requests to investigate abuse, unauthorized access attempts, or incident response for the exposed API surface.

## Summary
This check fails when an API Gateway stage (REST API or HTTP API/apigatewayv2) does not have an access log destination configured, meaning per-request access logs are not being delivered anywhere.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::ApiGateway::Stage`, `AWS::Serverless::Api` (CloudFormation/SAM), `aws_api_gateway_stage`, `aws_apigatewayv2_stage` (Terraform)
- **Check type:** resource

## Why it matters
API Gateway access logs record every incoming request — caller IP, request path, method, response status, latency, and (with custom formats) headers or identity claims. Without this, an organization has no durable record of who called which API endpoint, when, and with what result. This directly undermines incident response: if an API key or JWT is compromised and abused, there's no way to reconstruct the scope of unauthorized access (which resources were hit, how many records were potentially exfiltrated, from which source IPs) without access logs. It also removes a key detective control for identifying reconnaissance activity (e.g., systematic 403/404 probing) or abuse patterns (excessive request rates from a single caller) that precede a more serious exploitation attempt.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck` with expected value `ANY_VALUE` (i.e., pass as soon as *any* non-empty value is set — the destination doesn't need to be a specific ARN):
- **CloudFormation:** inspects `Properties/AccessLogSetting/DestinationArn` on `AWS::ApiGateway::Stage` / `AWS::Serverless::Api`.
- **Terraform:** inspects `access_log_settings/[0]/destination_arn` on `aws_api_gateway_stage` or `aws_apigatewayv2_stage`.
In both cases, the check fails if the `access_log_settings` / `AccessLogSetting` block is missing entirely, or present without a `destination_arn` / `DestinationArn`.

## Non-compliant example
```hcl
resource "aws_api_gateway_stage" "prod" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deploy.id
}
```

```yaml
Resources:
  ProdStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: prod
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref MyDeployment
```

## Remediated example
```hcl
resource "aws_cloudwatch_log_group" "api_access_logs" {
  name              = "/aws/apigateway/prod-access-logs"
  retention_in_days = 90
}

resource "aws_api_gateway_stage" "prod" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deploy.id

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access_logs.arn
    format          = jsonencode({
      requestId      = "$context.requestId"
      ip              = "$context.identity.sourceIp"
      caller          = "$context.identity.caller"
      httpMethod      = "$context.httpMethod"
      resourcePath    = "$context.resourcePath"
      status          = "$context.status"
      responseLength  = "$context.responseLength"
    })
  }
}
```

```yaml
Resources:
  ApiAccessLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/apigateway/prod-access-logs
      RetentionInDays: 90

  ProdStage:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: prod
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref MyDeployment
      AccessLogSetting:
        DestinationArn: !GetAtt ApiAccessLogGroup.Arn
        Format: '$context.requestId $context.identity.sourceIp $context.httpMethod $context.status'
```

## Remediation steps
1. Create a CloudWatch Log Group (or use an existing centralized logging destination) for API access logs.
2. Add an `access_log_settings` (Terraform) or `AccessLogSetting` (CloudFormation) block to the stage resource, pointing `destination_arn`/`DestinationArn` at that log group's ARN.
3. Grant API Gateway's account-level CloudWatch Logs role (`AmazonAPIGatewayPushToCloudWatchLogs` on the API Gateway account settings) permission to write to the log group.
4. Choose a log `format` that includes at least: request ID, source IP, identity/caller, method, path, and response status — richer formats aid investigations at marginal storage cost.
5. Set a retention period on the log group consistent with your compliance/retention policy to control cost while preserving investigative window.
6. Non-disruptive change; no downtime required.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayAccessLogging.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/APIGatewayAccessLogging.py)
- [AWS API Gateway access logging](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)
