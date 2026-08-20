# CKV_AWS_214: Ensure AppSync API Cache is encrypted at rest
## Severity
**LOW** (score: 2.0/10)

An unencrypted AppSync API cache can persist cached GraphQL response data (potentially including sensitive application data) in plaintext, exposing it to anyone with access to the underlying storage.

## Summary
This check ensures that an AWS AppSync API cache (`aws_appsync_api_cache`) has encryption at rest enabled, protecting cached GraphQL response data stored on disk.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_appsync_api_cache`

## Why it matters
AppSync's API caching feature stores the results of GraphQL resolver calls to reduce backend load and latency. Depending on your schema and caching TTLs, this cache can hold sensitive application data (user profile fields, business records, etc.) that would otherwise only live in your backing data store with its own access controls and encryption. If the cache is not encrypted at rest, that cached data sits as plaintext on the underlying storage medium, so anyone who gains access to the underlying infrastructure, storage snapshots, or a misconfigured backup could read sensitive response payloads without needing to compromise the GraphQL API or its backend data sources — bypassing the application-layer authorization AppSync enforces on the live path.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `at_rest_encryption_enabled` attribute:
- The check is configured with `missing_block_result=CheckResult.FAILED`, meaning if the attribute is not set at all, the check **FAILS** (unlike checks that default to PASS when a block is absent).
- If `at_rest_encryption_enabled` is explicitly set to `true`, the check **PASSES**.
- If it is `false` or absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_appsync_api_cache" "example" {
  api_id               = aws_appsync_graphql_api.example.id
  api_caching_behavior = "FULL_REQUEST_CACHING"
  type                 = "SMALL"
  ttl                  = 300
}
```

## Remediated example
```hcl
resource "aws_appsync_api_cache" "example" {
  api_id                    = aws_appsync_graphql_api.example.id
  api_caching_behavior      = "FULL_REQUEST_CACHING"
  type                      = "SMALL"
  ttl                       = 300
  at_rest_encryption_enabled = true
}
```

## Remediation steps
1. Add `at_rest_encryption_enabled = true` to the `aws_appsync_api_cache` resource.
2. Note: `at_rest_encryption_enabled` can only be set at cache creation time and cannot be modified afterward — enabling it on an existing unencrypted cache requires deleting and recreating the `aws_appsync_api_cache` resource, which will briefly disable caching (falling back directly to resolvers) during the change.
3. Consider also enabling `transit_encryption_enabled` (see CKV_AWS_215) at the same time, since both settings are similarly creation-time-only.
4. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AppsyncAPICacheEncryptionAtRest.py)
- [AWS AppSync: Caching](https://docs.aws.amazon.com/appsync/latest/devguide/enabling-caching.html)
