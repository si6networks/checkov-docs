# CKV2_GCP_20: Ensure MySQL DB instance has point-in-time recovery backup configured
## Severity
**LOW** (score: 2.0/10)

Missing point-in-time recovery on a MySQL Cloud SQL instance is primarily an availability/data-durability gap (limited ability to recover from corruption or accidental deletion) rather than a confidentiality exposure.

## Summary
This check ensures that Cloud SQL MySQL database instances have binary logging enabled, which is required for point-in-time recovery (PITR).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_sql_database_instance`

## Why it matters
Point-in-time recovery lets you restore a database to any specific moment (down to a transaction), not just to the timestamp of the last full backup snapshot. Without binary logging enabled, a MySQL Cloud SQL instance can only be restored to the point of its last scheduled backup — meaning any data written, corrupted, or maliciously deleted/modified between backups is unrecoverable. This is a critical business-continuity and incident-response gap: in a ransomware event, accidental `DROP TABLE`, or a bad migration, the difference between PITR and backup-only recovery can be hours or days of lost/corrupted data. This check does not apply to read replicas (which inherit recovery configuration from their master) or to non-MySQL engines, since the underlying mechanism (binary logs) is MySQL-specific.

## How Checkov evaluates this
This is a Terraform graph-based check that passes if **any** of the following are true for a `google_sql_database_instance`:
- The instance has a `master_instance_name` set (i.e., it's a read replica — PITR is managed via the master), **or**
- `database_version` does not contain `"MYSQL"` (i.e., it's Postgres/SQL Server — this check is MySQL-specific), **or**
- `settings.backup_configuration.binary_log_enabled` is set to `true`.
It **fails** only for standalone MySQL instances that have backups configured without binary logging enabled (or backups/binary logging entirely absent).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "mysql_instance" {
  name             = "prod-mysql"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-n1-standard-1"

    backup_configuration {
      enabled = true
      # binary_log_enabled not set -> no point-in-time recovery
    }
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "mysql_instance" {
  name             = "prod-mysql"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-n1-standard-1"

    backup_configuration {
      enabled            = true
      binary_log_enabled = true   # enables point-in-time recovery
    }
  }
}
```

## Remediation steps
1. Add `binary_log_enabled = true` inside the `backup_configuration` block of your `google_sql_database_instance` resource.
2. Ensure `backup_configuration.enabled = true` as well — binary logging requires automated backups to be turned on.
3. Binary logs consume additional storage; monitor storage usage and set appropriate `transaction_log_retention_days` if you need to tune log retention.
4. This setting can typically be applied to an existing running instance without downtime, but verify in a staging environment first since enabling binary logging does restart replication-related processes.
5. If the instance is a read replica (`master_instance_name` set), no action is needed — PITR is inherited from its master.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPMySQLdbInstancePoint_In_TimeRecoveryBackupIsEnabled.json
- GCP docs: https://cloud.google.com/sql/docs/mysql/backup-recovery/pitr
