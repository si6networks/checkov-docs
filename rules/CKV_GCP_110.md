# CKV_GCP_110: Ensure pgAudit is enabled for your GCP PostgreSQL database

## Severity
**LOW** (score: 2.0/10)

pgAudit provides detailed, session/object-level audit logging of database activity; its absence weakens the ability to detect and investigate unauthorized data access even though the database remains protected by other controls.

## Summary
This check ensures that a Cloud SQL PostgreSQL instance has the `cloudsql.enable_pgaudit` database flag set to `on`, enabling the pgAudit extension for detailed, session/object-level audit logging.

## Applicability
- **IaC framework**: Terraform
- **Resource type**: `google_sql_database_instance` (PostgreSQL engine)
- **Attribute inspected**: a `database_flags` block with `name = "cloudsql.enable_pgaudit"` and `value = "on"`

## Why it matters
Standard PostgreSQL logging (even with verbose settings) provides limited detail about *what data* was accessed by *whom* — it's oriented toward statement text and errors, not structured audit trails. pgAudit is the industry-standard PostgreSQL extension purpose-built for detailed audit logging: it can log every SELECT, DML statement, DDL change, role/permission change, and function call, per session and per object, in a format suitable for compliance and security review.

- **No detailed data-access audit trail without it**: Without pgAudit, you cannot reliably answer "who read/modified this specific row or table, and when" after the fact — a critical capability for detecting insider threats, investigating data breaches, and satisfying regulatory requirements (PCI-DSS, HIPAA, SOX all commonly require this level of database audit logging).
- **Cannot distinguish privileged/DDL changes from routine queries**: pgAudit's structured logging separates statement classes (READ, WRITE, ROLE, DDL, MISC), enabling automated alerting on suspicious classes of activity (e.g., unexpected DDL changes to a production schema) that generic statement logging can't cleanly support.
- **Weakens breach investigation and legal defensibility**: In a data-breach investigation, being able to show precisely which records were accessed (or that none were, beyond what's expected) is often the difference between a limited, well-scoped incident report and a maximal-assumption disclosure, since you can't prove a negative without the audit data.
- **Given the two flagged modules handle simulation and general data-pipeline databases**, enabling pgAudit provides the audit granularity needed to confirm data pipeline processes are only touching the tables/rows they're authorized for.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlEnablePgaudit`) uses the shared `AbsGooglePostgresqlDatabaseFlags` base class with `FLAG_NAME = "cloudsql.enable_pgaudit"` and `FLAG_VALUES = ["on"]`:
- **PASSES** if a `database_flags` entry has `name = "cloudsql.enable_pgaudit"` and `value = "on"`.
- **FAILS** if the flag is absent, or set to any value other than `"on"` (e.g., `"off"`).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "data-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-4-16384"
    # cloudsql.enable_pgaudit not set
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
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
  }
}
```

## Remediation steps
1. In `src/cloud/infra/terraform/simulations/modules/database/main.tf` and `src/cloud/infra/terraform/data/modules/postgresql/main.tf`, add a `database_flags` block with `name = "cloudsql.enable_pgaudit"` and `value = "on"` inside `settings` (alongside any other flags already configured).
2. After enabling the instance-level flag, also run `CREATE EXTENSION IF NOT EXISTS pgaudit;` on each database that should be audited, and configure the `pgaudit.log` parameter (also settable as a `database_flags` entry, e.g., `pgaudit.log = "write,ddl,role"`) to specify which statement classes to audit — enabling the extension flag alone does not configure what gets logged.
3. Applying the `cloudsql.enable_pgaudit` flag requires an instance restart — schedule during a maintenance window.
4. Plan for increased log volume: pgAudit with broad `pgaudit.log` settings can produce substantially more log data than default logging; size log retention/export (e.g., to a log sink or SIEM) accordingly.
5. Re-scan with Checkov and confirm via `gcloud sql instances describe` and a `SHOW cloudsql.enable_pgaudit;` query that the extension is active.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlEnablePgaudit.py
- GCP Cloud SQL pgAudit documentation: https://cloud.google.com/sql/docs/postgres/pg-audit
