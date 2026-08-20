# CKV_AWS_225: Ensure API Gateway method setting caching is enabled
## Severity
**LOW** (score: 2.0/10)

API Gateway method caching is primarily a performance/cost optimization (categorized under backup-and-recovery by Checkov); its absence has no direct confidentiality, integrity, or availability attack path.

## Summary
This check ensures that an `aws_api_gateway_method_settings` resource has response caching enabled (`caching_enabled = true`) for the associated API Gateway method.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_api_gateway_method_settings`

## Why it matters
This check is categorized under backup/recovery and resiliency rather than confidentiality. Enabling API Gateway response caching reduces the number of requests that hit backend integrations (Lambda functions, HTTP backends, etc.), which improves resilience under load spikes and reduces the chance that a backend outage or throttling event causes cascading failures visible to API clients. Without caching, every request — including bursts of identical/repeated requests — is forwarded directly to the backend, meaning a traffic spike (whether organic or from a denial-of-service style abuse pattern) translates directly into backend load, increasing the risk of backend exhaustion, increased latency, or outright unavailability. Caching effectively acts as an application-layer buffer that absorbs some of that load transparently.

Note: caching does introduce its own considerations — cached responses can serve stale data, and if the cache key isn't properly scoped to caller identity/authorization context, it can risk serving one user's cached (and potentially sensitive) response to another unauthorized caller. Any remediation should account for this.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute path `settings/[0]/caching_enabled`:
- If `caching_enabled` is `true`, the check **PASSES**.
- If it is `false` or absent, the check **FAILS** (default missing-block behavior, expected value defaults to `True`).

## Non-compliant example
```hcl
resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "ERROR"
  }
}
```

## Remediated example
```hcl
resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    logging_level      = "ERROR"
    caching_enabled    = true
    cache_ttl_in_seconds = 300
  }
}
```

## Remediation steps
1. Add `caching_enabled = true` inside the `settings` block of the `aws_api_gateway_method_settings` resource.
2. Ensure the associated `aws_api_gateway_stage` has `cache_cluster_enabled = true` and a `cache_cluster_size` configured — method-level caching requires a stage-level cache cluster to be provisioned, which incurs additional cost.
3. Set an appropriate `cache_ttl_in_seconds` balancing freshness needs against backend load reduction.
4. Verify the cache key parameters (`cache_key_parameters` on the method's integration/request) correctly scope caching per relevant request parameters (e.g. per-user auth token or path parameter) to avoid one caller's cached response leaking to a different, unauthorized caller.
5. Only enable caching for idempotent, cacheable (typically `GET`) methods — avoid caching responses for mutating operations.
6. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayMethodSettingsCacheEnabled.py)
- [AWS API Gateway: Enable API caching](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html)
