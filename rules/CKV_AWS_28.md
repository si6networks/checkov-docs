# CKV_AWS_28: Ensure DynamoDB point in time recovery (backup) is enabled
## Severity
**HIGH** (score: 7.5/10)

Missing point-in-time recovery on a DynamoDB table is an availability/resilience gap (inability to restore from accidental deletion or corruption) rather than a direct confidentiality or access-control weakness.

## Summary
This check fails when a DynamoDB table does not have Point-in-Time Recovery (PITR) enabled, leaving the table without continuous backups that can restore to any second in the last 35 days.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** Terraform, CloudFormation
- **Resources:** `aws_dynamodb_table` (Terraform), `AWS::DynamoDB::Table` (CloudFormation)

## Why it matters
Without PITR, the only recovery options for a DynamoDB table are manual on-demand backups (if someone remembered to take one) or nothing at all. This makes the table vulnerable to unrecoverable data loss from application bugs that corrupt or delete items, accidental `DeleteTable`/`BatchWriteItem` operations, a compromised IAM principal performing destructive writes, or a bad deployment that overwrites data. PITR is DynamoDB's equivalent of database transaction-log backup: it lets you restore the table to any point within the retention window (35 days by default) without needing to have manually scheduled a backup beforehand. For any table holding data that isn't trivially reproducible from another source (user records, transactional data, audit logs), the absence of PITR converts what should be a recoverable incident into permanent data loss.

## How Checkov evaluates this
**Terraform:** `BaseResourceValueCheck` inspects `point_in_time_recovery/[0]/enabled` on `aws_dynamodb_table`. It accepts either the boolean `true` or the string `'true'` (to tolerate Terraformer-exported state) as passing values; missing/false fails.

**CloudFormation:** `BaseResourceValueCheck` inspects `Properties/PointInTimeRecoverySpecification/PointInTimeRecoveryEnabled` on `AWS::DynamoDB::Table`; missing/false fails.

## Non-compliant example
```hcl
resource "aws_dynamodb_table" "example" {
  name         = "orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "OrderId"

  attribute {
    name = "OrderId"
    type = "S"
  }
  # point_in_time_recovery block omitted
}
```

## Remediated example
```hcl
resource "aws_dynamodb_table" "example" {
  name         = "orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "OrderId"

  attribute {
    name = "OrderId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}
```

## Remediation steps
1. Add a `point_in_time_recovery { enabled = true }` block to every `aws_dynamodb_table` (Terraform), or `PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true }` under `Properties` (CloudFormation).
2. No downtime or resource replacement is required — enabling PITR is an in-place, online operation.
3. Be aware PITR incurs additional storage cost proportional to the table's incremental changes over the retention window; budget for it on large/high-churn tables.
4. Combine with on-demand backups or AWS Backup plans for longer-than-35-day retention or cross-region/cross-account backup copies, since PITR alone only covers the rolling window.
5. Periodically test the restore procedure (`aws dynamodb restore-table-to-point-in-time`) so the team is not learning it for the first time during an incident.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DynamodbRecovery.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DynamodbRecovery.py
- AWS docs: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html
