# CKV_AWS_165: Ensure DynamoDB point in time recovery (backup) is enabled for global tables

## Severity
**MEDIUM** (score: 5.0/10)

Missing point-in-time recovery on a DynamoDB global table is a data-durability/availability gap (harder recovery from accidental deletion or corruption) rather than a confidentiality or access-control weakness.

## Summary
This check requires that DynamoDB global tables have point-in-time recovery (PITR) enabled on their replicas so that table data can be restored to any point within the retention window in the event of accidental writes/deletes or application bugs.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_dynamodb_global_table` (see important note below — the check is effectively a no-op for Terraform)
- **CloudFormation**: `AWS::DynamoDB::GlobalTable`

## Why it matters
Global tables replicate data across multiple AWS regions for high availability and low-latency global access. Because replication is near real-time, an accidental bulk delete, a buggy migration script, or a malicious/compromised write propagates to every replica almost immediately — there is no natural "safe" copy elsewhere in the system. Without point-in-time recovery, the only recovery options are periodic on-demand backups (if any were taken) or nothing at all, meaning data-loss incidents can become unrecoverable or force recovery from stale, manually-triggered backups with large gaps.

PITR maintains continuous backups (down to the second, typically over a 35-day window) that allow the table to be restored to any point in time, dramatically reducing the potential data-loss window from "since the last manual backup" to effectively zero for recent history.

## How Checkov evaluates this
**CloudFormation**: the check inspects `Properties.Replicas[0].PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled` on `AWS::DynamoDB::GlobalTable` and fails unless it is explicitly `true`.

**Terraform**: notably, the Terraform implementation's `scan_resource_conf` **always returns `CheckResult.PASSED` unconditionally**, regardless of configuration. The check's own source comment explains why: the `aws_dynamodb_global_table` Terraform resource does not expose a point-in-time-recovery argument at all (PITR for global tables in Terraform is instead configured on the underlying regional `aws_dynamodb_table` resources' `point_in_time_recovery` blocks, which are covered by a different, more general Checkov check). So for Terraform users, this specific check ID will never fire — you must instead ensure `point_in_time_recovery { enabled = true }` is set on each regional `aws_dynamodb_table` that participates in the global table.

## Non-compliant example
```yaml
# CloudFormation (YAML)
Resources:
  GlobalTable:
    Type: AWS::DynamoDB::GlobalTable
    Properties:
      TableName: orders
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST
      Replicas:
        - Region: us-east-1
        - Region: eu-west-1
          # PointInTimeRecoverySpecification not set -> disabled
```

## Remediated example
```yaml
# CloudFormation (YAML)
Resources:
  GlobalTable:
    Type: AWS::DynamoDB::GlobalTable
    Properties:
      TableName: orders
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST
      Replicas:
        - Region: us-east-1
          PointInTimeRecoverySpecification:
            PointInTimeRecoveryEnabled: true   # added
        - Region: eu-west-1
          PointInTimeRecoverySpecification:
            PointInTimeRecoveryEnabled: true   # added
```

## Remediation steps
1. In CloudFormation, set `PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled: true` under **each** entry in the `Replicas` list — it must be specified per-replica, not just once globally.
2. In Terraform, this Checkov check will always pass regardless of your configuration; instead, ensure PITR is enabled on each region's underlying table using the standalone `aws_dynamodb_table` resource's `point_in_time_recovery { enabled = true }` block (tracked by a separate Checkov rule, e.g. CKV_AWS_28), since `aws_dynamodb_global_table` itself has no such argument.
3. Enabling PITR is a non-disruptive, in-place change with no downtime or replacement.
4. Note PITR only covers continuous point-in-time restores within the retention window (up to 35 days); combine with on-demand backups or exports to S3 for longer-term/compliance retention needs.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DynamoDBGlobalTableRecovery.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DynamodbGlobalTableRecovery.py
- AWS docs: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html
