# CKV_AWS_73: Ensure API Gateway has X-Ray Tracing enabled
## Severity
**LOW** (score: 2.0/10)

Disabled X-Ray tracing only reduces distributed-tracing observability for API Gateway requests and has no direct confidentiality, integrity, or availability impact on its own.

## Summary
This check fails when an API Gateway stage does not have AWS X-Ray active tracing enabled, meaning distributed request traces through the API are not captured.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::ApiGateway::Stage`, `AWS::Serverless::Api` (CloudFormation/SAM), `aws_api_gateway_stage` (Terraform)
- **Check type:** resource

## Why it matters
X-Ray tracing on an API Gateway stage captures per-request latency, error, and fault data as requests flow from the API Gateway edge through backend integrations (Lambda, HTTP backends, VPC links). Without it, operators lose visibility into where failures or high-latency segments occur in the request path, which materially slows incident response for both operational outages and security investigations (e.g., correlating unusual latency/error spikes with an attack such as a slow-loris style abuse or a downstream dependency being probed). It also weakens the ability to reconstruct end-to-end request flow during a security incident that touches multiple services behind the same API, since X-Ray traces provide a correlated, cross-service audit view that access logs alone don't fully replicate.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck` with expected value `True`:
- **CloudFormation:** inspects `Properties/TracingEnabled` on `AWS::ApiGateway::Stage` / `AWS::Serverless::Api`; passes only if this is explicitly `true`.
- **Terraform:** inspects the `xray_tracing_enabled` attribute on `aws_api_gateway_stage`; passes only if it is explicitly `true`. If the attribute is absent (Terraform's default is `false`) or set to `false`, the check fails.

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
resource "aws_api_gateway_stage" "prod" {
  stage_name           = "prod"
  rest_api_id          = aws_api_gateway_rest_api.api.id
  deployment_id        = aws_api_gateway_deployment.deploy.id
  xray_tracing_enabled = true
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
      TracingEnabled: true
```

## Remediation steps
1. Set `xray_tracing_enabled = true` on the `aws_api_gateway_stage` resource (Terraform), or `TracingEnabled: true` under `Properties` (CloudFormation/SAM).
2. Ensure the API Gateway execution role / associated Lambda execution roles have the `AWSXRayDaemonWriteAccess` managed policy (or equivalent `xray:PutTraceSegments`, `xray:PutTelemetryRecords` permissions) so traces can actually be written.
3. If backend Lambda functions are involved, also enable active tracing on those functions (`tracing_config { mode = "Active" }`) for full end-to-end traces.
4. This is a non-disruptive configuration change with no downtime.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayXray.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/APIGatewayXray.py)
- [AWS X-Ray and API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-xray.html)
