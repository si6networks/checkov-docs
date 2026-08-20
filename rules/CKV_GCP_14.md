# CKV_GCP_14: Ensure all Cloud SQL database instance have backup configuration enabled
## Severity
**HIGH** (score: 7.5/10)

Missing automated backups on a Cloud SQL instance does not expose data directly but risks unrecoverable data loss after corruption, accidental deletion, or a ransomware-style incident, an availability/integrity impact rather than a direct confidentiality breach.

## Summary
This check fails when a `google_sql_database_instance` resource does not explicitly enable automated backups in its `settings.backup_configuration` block.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_sql_database_instance`
- **Check type:** resource (Terraform plan/config attribute check)

## Why it matters
Cloud SQL instances hold operational and often business-critical relational data. Without automated backups enabled, a database suffering accidental data deletion, a bad migration, ransomware/compromise, storage corruption, or an unintended `terraform destroy`/instance failure has no recovery path other than manual, ad-hoc snapshots (if anyone remembered to take one). Automated backups are also a prerequisite for point-in-time recovery on Cloud SQL, and for cross-region disaster-recovery replicas. Disabling backups trades a trivial cost saving for an unbounded, hard-to-quantify data-loss risk.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the attribute path:

```
settings[0].backup_configuration[0].enabled
```

- **PASS** — `backup_configuration.enabled` is present and set to `true`.
- **FAIL** — the attribute is missing, or explicitly set to `false`.
- **Special case:** if the resource configuration contains `master_instance_name` (i.e., the instance is a **read replica**, not a primary), the check returns `UNKNOWN` and is skipped — replicas inherit backup semantics from their primary and don't have independent backup configuration in the same sense.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "app-db"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"
    # backup_configuration block omitted entirely -> FAILS
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "app-db"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "02:00"
      transaction_log_retention_days = 7
    }
  }
}
```

## Remediation steps
1. Add a `backup_configuration` block inside `settings` on every `google_sql_database_instance` (primary instances only — read replicas are exempt).
2. Set `enabled = true`.
3. For production workloads, also set `point_in_time_recovery_enabled = true` (PostgreSQL/MySQL) so you can restore to any point within the retention window, not just to the last backup.
4. Choose a `start_time` in a low-traffic window (backups can add I/O load).
5. Review `backup_retention_settings.retained_backups` if you need a longer retention window than the 7-day default.
6. This is an in-place update in Terraform (no instance replacement/downtime required) — apply and confirm via `gcloud sql instances describe`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudSqlBackupConfiguration.py
- GCP docs: https://cloud.google.com/sql/docs/mysql/backup-recovery/backups
