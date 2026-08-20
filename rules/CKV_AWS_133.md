# CKV_AWS_133: Ensure that RDS instances has backup policy

## Severity
**LOW** (score: 2.0/10)

Missing automated RDS backups is primarily an availability/recoverability gap (data loss on failure or accidental deletion) rather than a direct confidentiality or access-control weakness.

## Summary
This check requires `aws_db_instance` and `aws_rds_cluster` resources to have a `backup_retention_period` set to a value between 1 and 35 days, ensuring automated backups are retained for a meaningful window.

## Applicability
- **Framework:** Terraform (AWS provider)
- **Resource types:** `aws_db_instance`, `aws_rds_cluster`

## Why it matters
`backup_retention_period = 0` disables automated backups entirely for RDS. Without automated backups (and the point-in-time recovery they enable), there is no way to recover from accidental data deletion, a botched migration/schema change, ransomware-style data corruption, or a malicious/compromised-credential `DROP TABLE`/`DELETE` event, other than whatever ad-hoc manual snapshots happen to exist. This is a foundational business-continuity and incident-recovery control — losing automated backups converts what should be a recoverable incident (roll back to a point 10 minutes before the bad change) into permanent data loss.

## How Checkov evaluates this
The check (`DBInstanceBackupRetentionPeriod`, `BaseResourceCheck`) inspects `backup_retention_period`:
- If the key is present but is a Terraform variable reference that can't be resolved, result is **UNKNOWN**.
- If present and resolvable, it coerces to int: **PASS** if `0 < period <= 35`; otherwise **FAIL** (this includes `period == 0`, negative values, or values above the AWS-imposed 35-day maximum).
- If the key is **absent entirely**, the check **PASSES** — the code comment notes the AWS default value for `backup_retention_period` is `1` day, which is itself compliant.

So omitting the attribute is fine (AWS default of 1 day applies); explicitly setting it to `0` is what fails the check.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier             = "app-db"
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  allocated_storage      = 50
  username               = "admin"
  password               = var.db_password
  backup_retention_period = 0   # FAIL: automated backups disabled
}
```

## Remediated example
```hcl
resource "aws_db_instance" "app_db" {
  identifier             = "app-db"
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  allocated_storage      = 50
  username               = "admin"
  password               = var.db_password
  backup_retention_period = 7   # PASS: 7-day automated backup retention
}
```

## Remediation steps
1. Set `backup_retention_period` to a value between 1 and 35 days on every `aws_db_instance` and `aws_rds_cluster`. A common baseline is 7 days; regulatory or compliance requirements may dictate longer (up to the 35-day ceiling).
2. If the attribute is already omitted, it is compliant by default — but consider setting it explicitly for clarity and to avoid relying on implicit provider defaults.
3. For longer-term retention beyond 35 days, pair automated backups with a separate backup solution such as AWS Backup or scheduled manual snapshots exported to S3/Glacier.
4. Changing `backup_retention_period` from `0` to a positive value may require a brief maintenance window on some engines/configurations since it can trigger a modification event; check the `apply_immediately` setting behavior for your engine.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DBInstanceBackupRetentionPeriod.py)
- [AWS: Working with backups for Amazon RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html)
