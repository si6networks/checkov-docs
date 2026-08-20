# CKV_AWS_308: Ensure API Gateway method setting caching is set to encrypted
## Severity
**HIGH** (score: 7.5/10)

This check verifies API Gateway method-level caching is configured with cache_data_encrypted; unencrypted method caches could expose cached request/response data (potentially including sensitive parameters) to anyone with access to the underlying cache storage.

## Summary
This check ensures that on an `aws_api_gateway_method_settings` resource, if response caching is enabled (`caching_enabled = true`), then `cache_data_encrypted` must also be set to `true` so cached API responses are encrypted at rest.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_api_gateway_method_settings`

## Why it matters
API Gateway method-level caching stores the actual response bodies returned by your backend so repeat requests can be served without invoking the integration again. If those responses contain sensitive data — user profile details, tokens, PII, or any authenticated user-specific payload — an unencrypted cache means that data sits in a shared, longer-lived storage layer without cryptographic protection. Anyone with access to the underlying cache infrastructure (which is managed by AWS but still represents an additional data-at-rest surface outside your direct application boundary) could potentially access historical response data, and the exposure window persists for the configured TTL of the cache entry, independent of how long the original request/response was in flight. This is tied to NIST 800-53 controls around cryptographic protection of data at rest and in transient system components (SC-13, SC-28, SC-28(1)).

## How Checkov evaluates this
This is a `BaseResourceValueCheck`-derived check with custom `scan_resource_conf` logic. It inspects the `settings` block:
- If `caching_enabled` is `false` (or unset, defaulting to `False`), the check **PASS**es unconditionally — encryption of a disabled cache is not applicable.
- If `caching_enabled` is `true`, the check then looks at `cache_data_encrypted` (also defaulting to `False` if unset): **FAIL** if it is falsy; **PASS** if it is `true`.

## Non-compliant example
```hcl
resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    caching_enabled = true
    # cache_data_encrypted not set -> defaults to false while caching is on, check FAILS
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
    caching_enabled       = true
    cache_data_encrypted  = true   # encrypt cached response data at rest
  }
}
```

## Remediation steps
1. Wherever `caching_enabled = true` is set in an `aws_api_gateway_method_settings.settings` block, also add `cache_data_encrypted = true`.
2. Be aware that enabling cache encryption can add latency to cache read/write operations — evaluate the performance impact for latency-sensitive APIs, though this is usually a worthwhile tradeoff for endpoints returning sensitive data.
3. If the cached responses genuinely contain no sensitive data (e.g., fully public, non-personalized content), you may consciously accept the risk and document the exception, but default to encrypting whenever in doubt.
4. Confirm the underlying API Gateway stage has an appropriate `cache_cluster_size` configured, since caching (and thus this setting) has no effect unless a cache cluster is provisioned for the stage.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayMethodSettingsCacheEncrypted.py)
