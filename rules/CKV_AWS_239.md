# CKV_AWS_239: Ensure DAX cluster endpoint is using TLS

## Severity
**HIGH** (score: 7.0/10)

Without TLS on the DAX cluster endpoint, all client traffic to the in-memory cache travels in plaintext, exposing cached application data (often mirroring sensitive DynamoDB records) to anyone able to observe traffic on the VPC.

## Summary
This check ensures that an Amazon DynamoDB Accelerator (DAX) cluster's `cluster_endpoint_encryption_type` is set to `TLS`, so client connections to the cluster endpoint are encrypted in transit.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_dax_cluster`

## Why it matters
DAX is an in-memory caching layer that sits in front of DynamoDB, and client applications connect directly to the DAX cluster endpoint to read/write cached items — often the same sensitive application data (user records, session tokens, financial data, etc.) that would otherwise go straight to DynamoDB. If the cluster endpoint encryption type is not set to `TLS` (AWS's other option is `NONE`, i.e. plaintext), all traffic between application clients and the DAX cluster travels unencrypted over the network. Any party able to observe traffic on the VPC (a compromised host on the same subnet, a misconfigured VPC peering/mirroring setup, or an attacker who has gained a foothold elsewhere in the network) can passively capture the full contents of cached reads and writes, including any sensitive data cached from DynamoDB. Since DAX clusters commonly sit in the same private subnets as application tiers precisely because they're assumed to be "internal," it's easy to underestimate the risk of leaving this in plaintext — but internal network segments are not inherently trusted, especially in shared VPC or multi-tenant environments.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `cluster_endpoint_encryption_type` attribute of the `aws_dax_cluster` resource.
- **PASS** if `cluster_endpoint_encryption_type` is explicitly set to `"TLS"`.
- **FAIL** if the attribute is absent, or set to any other value (e.g. `"NONE"`).

## Non-compliant example
```hcl
resource "aws_dax_cluster" "cache" {
  cluster_name       = "app-cache"
  iam_role_arn       = aws_iam_role.dax.arn
  node_type          = "dax.r5.large"
  replication_factor = 3
}
```

## Remediated example
```hcl
resource "aws_dax_cluster" "cache" {
  cluster_name                 = "app-cache"
  iam_role_arn                 = aws_iam_role.dax.arn
  node_type                    = "dax.r5.large"
  replication_factor           = 3
  cluster_endpoint_encryption_type = "TLS"
}
```

## Remediation steps
1. Add `cluster_endpoint_encryption_type = "TLS"` to the `aws_dax_cluster` resource.
2. Update client-side DAX SDK configuration to use the TLS-aware DAX client (the standard AWS DAX SDKs support TLS connections out of the box once the cluster is configured for it) — application code changes may be required if the client library was pinned to a non-TLS mode.
3. Be aware that `cluster_endpoint_encryption_type` cannot be changed on an existing cluster; changing it forces Terraform to replace the DAX cluster, which involves downtime while the new cluster warms its cache from DynamoDB.
4. Combine with `server_side_encryption` (encryption at rest) on the same resource for full encryption coverage, since this check only addresses transit encryption.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DAXEndpointTLS.py)
- [Amazon DynamoDB Accelerator (DAX): Encryption in transit](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html)
