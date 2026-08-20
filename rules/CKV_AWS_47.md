# CKV_AWS_47: Ensure DAX is encrypted at rest (default is unencrypted)
## Severity
**LOW** (score: 2.0/10)

DAX is an in-memory cache fronting DynamoDB and commonly holds sensitive application data; leaving it unencrypted at rest exposes that cached data if the underlying nodes or storage are ever accessed improperly.

## Summary
This check ensures Amazon DynamoDB Accelerator (DAX) clusters have server-side encryption enabled, since DAX clusters are unencrypted by default.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::DAX::Cluster` (CloudFormation), `aws_dax_cluster` (Terraform)

## Why it matters
DAX is an in-memory caching layer that sits in front of DynamoDB to reduce read latency, and it often caches the exact same sensitive data (user records, session tokens, financial data) that lives in the backing DynamoDB tables. Unlike DynamoDB itself (encrypted at rest by default), DAX clusters are **not** encrypted at rest by default — an easy-to-miss gap since teams may assume the same default protections apply. If the underlying node storage or a memory/disk artifact is ever exposed (e.g., through improper node decommissioning or a misconfigured snapshot/backup), unencrypted cached data would be directly readable, undermining any encryption-at-rest guarantees made for the DynamoDB table itself.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` with an expected value of `true`:
- **CloudFormation:** inspects `Properties/SSESpecification/SSEEnabled` on `AWS::DAX::Cluster` — **PASS** if `true`, **FAIL** if `false` or absent.
- **Terraform:** inspects `server_side_encryption[0].enabled` on `aws_dax_cluster` — **PASS** if `true`, **FAIL** if `false`, or if the `server_side_encryption` block is entirely absent (DAX defaults to unencrypted).

## Non-compliant example
```hcl
resource "aws_dax_cluster" "example" {
  cluster_name       = "example-dax"
  iam_role_arn       = aws_iam_role.dax.arn
  node_type          = "dax.r4.large"
  replication_factor = 1
  # server_side_encryption not set -> defaults to unencrypted
}
```

## Remediated example
```hcl
resource "aws_dax_cluster" "example" {
  cluster_name       = "example-dax"
  iam_role_arn       = aws_iam_role.dax.arn
  node_type          = "dax.r4.large"
  replication_factor = 1

  server_side_encryption {
    enabled = true
  }
}
```

## Remediation steps
1. Add a `server_side_encryption { enabled = true }` block to the `aws_dax_cluster` resource (or set `Properties/SSESpecification/SSEEnabled: true` in CloudFormation).
2. **Important:** DAX server-side encryption cannot be changed on an existing cluster — this attribute requires resource replacement. Plan a cutover: create a new encrypted DAX cluster, point application clients at the new cluster endpoint, then decommission the old one.
3. Confirm the DAX cluster's IAM role has the necessary permissions unaffected by the change (encryption uses an AWS-owned key managed internally by DAX; no additional KMS key policy configuration is required).
4. Test cache warm-up behavior after cutover since the new cluster starts with an empty cache.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DAXEncryption.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DAXEncryption.py)
- [AWS DAX encryption at rest documentation](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAX.encryption.html)
