# CKV_AWS_120: Ensure API Gateway caching is enabled

## Severity
**LOW** (score: 2.0/10)

API Gateway caching is a performance/cost optimization; disabling it has no meaningful confidentiality, integrity, or access-control impact.

## Summary
Fails when an API Gateway (REST API) stage does not have response caching enabled.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_api_gateway_stage` resource.
- **CloudFormation/SAM**: `AWS::ApiGateway::Stage`, `AWS::Serverless::Api`.

## Why it matters
This check is categorized under "Backup and Recovery" / general resiliency rather than pure confidentiality, but caching has real security-adjacent implications too:
- **Availability/resiliency**: Without caching, every request is forwarded to the backend integration (Lambda, HTTP endpoint, etc.), so traffic spikes or repeated identical requests directly load the backend, increasing the risk of throttling, cascading failures, or increased latency during load spikes — caching absorbs repeat read traffic and smooths backend load.
- **Reduced attack surface for backend resource exhaustion**: An attacker (or a buggy client) hammering an endpoint with repeated identical GETs will hit the API Gateway cache instead of exhausting backend compute/database resources, mitigating a class of application-layer denial-of-service.
- **Consistency caveat**: Caching must be paired with correct TTL and per-user cache-key configuration (e.g. including auth context) to avoid inadvertently serving cached responses across different authorization contexts — a real risk if enabled carelessly, so this isn't a "just turn it on" control without also reviewing cache key configuration.

## How Checkov evaluates this
A straightforward `BaseResourceValueCheck` looking for a truthy value:
- **Terraform**: `cache_cluster_enabled` on `aws_api_gateway_stage` — fails if `false` or unset.
- **CloudFormation/SAM**: `Properties/CacheClusterEnabled` on `AWS::ApiGateway::Stage` / `AWS::Serverless::Api` — fails if `false` or unset.

## Non-compliant example
```hcl
resource "aws_api_gateway_stage" "bad" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.this.id
  deployment_id = aws_api_gateway_deployment.this.id
  # cache_cluster_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_api_gateway_stage" "good" {
  stage_name           = "prod"
  rest_api_id          = aws_api_gateway_rest_api.this.id
  deployment_id        = aws_api_gateway_deployment.this.id
  cache_cluster_enabled = true
  cache_cluster_size    = "0.5"
}

resource "aws_api_gateway_method_settings" "good" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.good.stage_name
  method_path = "*/*"

  settings {
    caching_enabled      = true
    cache_ttl_in_seconds = 300
  }
}
```

## Remediation steps
1. Set `cache_cluster_enabled = true` and choose an appropriate `cache_cluster_size` (e.g. `"0.5"` GB up to `"237"` GB) based on expected response payload sizes and cache hit-rate goals.
2. Enable caching per-method via `aws_api_gateway_method_settings` (`caching_enabled = true`) — enabling the cluster alone doesn't cache anything until methods are configured to use it.
3. Set an appropriate `cache_ttl_in_seconds` balancing freshness needs against backend load reduction.
4. Ensure caching is only applied to idempotent, non-sensitive-per-user GET endpoints, or explicitly configure cache key parameters (`cache_key_parameters` on the integration) to include auth/user-scoping values, to avoid cross-user response leakage.
5. Be aware enabling the cache cluster incurs additional hourly cost proportional to `cache_cluster_size`, independent of request volume.
6. For endpoints returning sensitive or highly dynamic data, it may be legitimately correct to leave caching disabled — document such exceptions rather than blanket-enabling caching everywhere.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayCacheEnable.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/APIGatewayCacheEnable.py
- AWS documentation: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
