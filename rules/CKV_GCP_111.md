# CKV_GCP_111: Ensure GCP PostgreSQL logs SQL statements

## Severity
**MEDIUM** (score: 5.0/10)

Failing to log DDL and data-modifying SQL statements removes an important audit trail for detecting unauthorized schema changes or data tampering after the fact.

## Summary
This check ensures that a Cloud SQL PostgreSQL instance's `log_statement` database flag is set to `ddl`, `mod`, or `all`, so that data-definition (or broader) SQL statements executed against the database are logged.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource type**: `google_sql_database_instance` (PostgreSQL engine)
- **Attribute inspected**: a `database_flags` block with `name = "log_statement"` whose `value` is one of `ddl`, `mod`, or `all`

## Why it matters
PostgreSQL's `log_statement` parameter controls which class of SQL statements get written to the server log, independent of whether they error. The default is `none`, meaning statements are not logged at all unless they fail (subject to `log_min_error_statement`). For the flagged simulations and data-pipeline database modules in this repo:

- **`none` (the default) means routine, successful statements leave no trace**: If an unauthorized party gains database access (via a leaked credential or exploited application flaw) and runs successful queries or data modifications, there is no log record at all of what was executed, because it never errored — only failures get logged without this flag set.
- **DDL changes need traceability**: Schema changes (`CREATE`, `ALTER`, `DROP`) are high-impact operations; logging at least `ddl` ensures every structural change to the database is recorded, supporting change-management review and detection of unauthorized schema tampering.
- **Data modification traceability**: Setting `mod` (which includes DDL plus `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`) captures every write to data, which is often required to reconstruct what changed and when in a data-integrity incident, especially important for pipeline databases like the ones flagged here that ingest data from external sources (simulations, general ETL).
- **`all` provides the most complete picture** (including reads) but at the highest log-volume cost — appropriate for highly sensitive databases where read access itself must be audited.
- Combined with `cloudsql.enable_pgaudit` (CKV_GCP_110), `log_statement` provides baseline coverage even without the pgAudit extension configured for specific classes.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogStatement`) uses the shared `AbsGooglePostgresqlDatabaseFlags` base class with `FLAG_NAME = "log_statement"` and `FLAG_VALUES = ["ddl", "mod", "all"]`:
- **PASSES** if a `database_flags` entry has `name = "log_statement"` and `value` is one of `ddl`, `mod`, or `all`.
- **FAILS** if the flag is absent, or set to `"none"` (the PostgreSQL default) or another unlisted value.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "data-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-4-16384"
    # log_statement not set — defaults to "none"
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "data-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-4-16384"

    database_flags {
      name  = "log_statement"
      value = "mod"
    }
  }
}
```

## Remediation steps
1. In `src/cloud/infra/terraform/simulations/modules/database/main.tf` and `src/cloud/infra/terraform/data/modules/postgresql/main.tf`, add or update a `database_flags` block with `name = "log_statement"` and `value` set to `ddl` (minimum), `mod` (recommended for data-pipeline databases where writes matter), or `all` (maximum, for highly sensitive data).
2. Add this as an additional `database_flags` block alongside any existing flags (`log_hostname`, `log_min_error_statement`, `cloudsql.enable_pgaudit`) rather than replacing them.
3. This flag change requires a Cloud SQL instance restart to take effect — schedule during a maintenance window.
4. Evaluate log volume and cost impact before choosing `mod` vs `all`; `all` will log every SELECT as well and can substantially increase log storage/export costs on high-throughput instances.
5. Re-scan with Checkov and verify via `gcloud sql instances describe` that `log_statement` is set to an accepted value.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogStatement.py
- GCP Cloud SQL PostgreSQL flags documentation: https://cloud.google.com/sql/docs/postgres/flags
- PostgreSQL `log_statement` documentation: https://www.postgresql.org/docs/current/runtime-config-logging.html
