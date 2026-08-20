# CKV_AWS_215: Ensure AppSync API Cache is encrypted in transit
## Severity
**LOW** (score: 2.0/10)

Disabling transit encryption on an AppSync API cache allows cached data to move between the API and cache nodes in cleartext, exposing it to interception on the internal network path.

## Summary
This check ensures that an AWS AppSync API cache (`aws_appsync_api_cache`) has encryption in transit enabled, protecting cached data as it moves between the AppSync service and the underlying cache nodes.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_appsync_api_cache`

## Why it matters
The AppSync API cache runs as a managed caching layer (backed by ElastiCache-style infrastructure) that is logically separate from the AppSync API endpoint itself; requests and responses travel over the network between AppSync and the cache nodes. If transit encryption is disabled, that internal traffic is sent in plaintext. While this traffic stays within AWS's network rather than the public internet, plaintext internal traffic is still vulnerable to interception by anyone who can observe traffic within the VPC/network path (e.g. via a compromised host, a misconfigured VPC peering/mirroring setup, or an insider threat with network visibility), potentially exposing cached GraphQL response data — including any sensitive fields the schema resolvers return.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `transit_encryption_enabled` attribute:
- The check is configured with `missing_block_result=CheckResult.FAILED`, meaning if the attribute is not set at all, the check **FAILS**.
- If `transit_encryption_enabled` is explicitly set to `true`, the check **PASSES**.
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
  api_id                     = aws_appsync_graphql_api.example.id
  api_caching_behavior       = "FULL_REQUEST_CACHING"
  type                       = "SMALL"
  ttl                        = 300
  transit_encryption_enabled = true
}
```

## Remediation steps
1. Add `transit_encryption_enabled = true` to the `aws_appsync_api_cache` resource.
2. Note: `transit_encryption_enabled` can only be set at cache creation time and cannot be modified afterward — enabling it on an existing cache requires deleting and recreating the resource, briefly disabling caching during the change.
3. Pair with `at_rest_encryption_enabled = true` (see CKV_AWS_214) to fully encrypt the cache both at rest and in transit, since both are creation-time-only settings best set together.
4. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AppsyncAPICacheEncryptionInTransit.py)
- [AWS AppSync: Caching](https://docs.aws.amazon.com/appsync/latest/devguide/enabling-caching.html)
