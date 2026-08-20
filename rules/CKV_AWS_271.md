# CKV_AWS_271: Ensure DynamoDB table replica KMS encryption uses CMK

## Severity
**HIGH** (score: 7.5/10)

DynamoDB global table replicas hold full copies of potentially sensitive application data, and omitting a customer-managed key can leave a replica under a less-governed key policy than its source table, breaking consistent multi-region access control.

## Summary
This check ensures that a DynamoDB global table replica (`aws_dynamodb_table_replica`) specifies a customer-managed KMS key ARN for encrypting the replicated table data.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: resource `aws_dynamodb_table_replica`

## Why it matters
DynamoDB global tables replicate an entire table's data across regions for low-latency access and disaster recovery. Each replica is a full, independent copy of potentially sensitive application data. If a replica does not explicitly specify a customer-managed key, its encryption can end up depending on defaults that may differ from the source table's carefully governed key policy — creating an inconsistency where the primary table is protected by a tightly scoped CMK but a replica in another region is protected by a less-controlled key (or a different key with a broader access policy). This undermines the principle that "backup/replica copies must have equivalent protection to the primary," a common audit finding when data-residency or key-governance policies aren't consistently enforced multi-region.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on the `kms_key_arn` attribute:
- **PASS**: `kms_key_arn` is set to any non-empty value.
- **FAIL**: `kms_key_arn` is absent or empty.

## Non-compliant example
```hcl
resource "aws_dynamodb_table_replica" "eu_replica" {
  global_table_arn = aws_dynamodb_table.main.arn
  # no kms_key_arn specified
}
```

## Remediated example
```hcl
resource "aws_dynamodb_table_replica" "eu_replica" {
  global_table_arn = aws_dynamodb_table.main.arn
  kms_key_arn       = aws_kms_key.dynamodb_eu.arn   # CMK in the replica's region
}
```

## Remediation steps
1. Create a customer-managed KMS key in each region hosting a replica (KMS keys are regional, so you cannot reuse the primary table's key ARN directly for a replica in a different region).
2. Set `kms_key_arn` on each `aws_dynamodb_table_replica` resource to the appropriate regional CMK.
3. Align the key policies across regions so access control is consistent between the primary table and all its replicas (e.g., via a standardized policy module).
4. Grant application roles operating in each region the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions for their local replica's key.
5. Note: enabling/changing CMK-based encryption on an existing global table replica can require careful sequencing (DynamoDB does support updating SSE settings without full table recreation in most cases, but validate against your provider version and current AWS API support before applying to production).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DynamoDBTableReplicaKMSUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GlobalTables.html
