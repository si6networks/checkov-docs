# CKV_AWS_95: Ensure API Gateway V2 has Access Logging enabled

## Severity
**LOW** (score: 2.0/10)

Missing access logging on API Gateway V2 removes a key detective control for identifying abuse, unauthorized access attempts, or anomalous API usage after the fact.

## Summary
This check fails when an HTTP API (API Gateway V2) stage — defined directly or via SAM's `AWS::Serverless::HttpApi` shorthand — does not configure an `AccessLogSettings.DestinationArn`, meaning access logging is not set up for that stage.

## Applicability
**Checkov framework(s):** `cloudformation`

- **CloudFormation** (including AWS SAM): `AWS::ApiGatewayV2::Stage` and `AWS::Serverless::HttpApi` resources — inspects `Properties.AccessLogSettings.DestinationArn`.

## Why it matters
API Gateway V2 (HTTP APIs) is the entry point for many serverless and microservice architectures, often fronting Lambda functions or other backend integrations that are directly reachable from the internet. Without access logging configured, there is no built-in record of who called which route, when, with what status code, or from what source IP. During a security investigation (e.g., suspected API abuse, credential-stuffing against an auth endpoint, or a data-exfiltration attempt via a poorly-scoped GET/query endpoint) the access log is frequently the only artifact showing what actually happened at the edge — Lambda execution logs alone often don't capture requests that were rejected before reaching the function (e.g., by throttling, authorizers, or CORS). Enabling `AccessLogSettings.DestinationArn` (pointing at a CloudWatch Logs group) is a low-cost control that establishes this baseline visibility.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using the special `ANY_VALUE` sentinel: it inspects `Properties/AccessLogSettings/DestinationArn` and passes as long as *any* non-empty value is present at that key (it does not validate that the ARN points to a real/valid log group — only that the field is populated). If the key is absent → FAILED.

## Non-compliant example
```yaml
Resources:
  MyHttpApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: !Ref MyHttpApi
      StageName: prod
      AutoDeploy: true
      # No AccessLogSettings configured
```

## Remediated example
```yaml
Resources:
  ApiAccessLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/apigateway/my-http-api
      RetentionInDays: 90

  MyHttpApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: !Ref MyHttpApi
      StageName: prod
      AutoDeploy: true
      AccessLogSettings:
        DestinationArn: !GetAtt ApiAccessLogGroup.Arn
        Format: '{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","status":"$context.status","routeKey":"$context.routeKey"}'
```

## Remediation steps
1. Create a CloudWatch Logs log group to receive access logs.
2. Add an `AccessLogSettings` block to the `AWS::ApiGatewayV2::Stage` (or the `HttpApi`'s implicit `$default` stage under `AWS::Serverless::HttpApi`) with `DestinationArn` set to that log group's ARN and a `Format` string covering the fields you need for audits.
3. Grant API Gateway's service-linked permissions (or the account-level CloudWatch Logs role for API Gateway) permission to write to the log group.
4. Set a retention period on the log group to balance audit needs against cost.
5. Consider shipping these logs to a SIEM or long-term storage (e.g., via a subscription filter to S3/OpenSearch) if compliance requires retention beyond CloudWatch's practical window.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/APIGatewayV2AccessLogging.py
- AWS docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html
