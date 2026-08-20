# CKV_GCP_52: Ensure PostgreSQL database 'log_connections' flag is set to 'on'

## Severity
**LOW** (score: 2.0/10)

Disabling connection logging removes an audit trail of who connected to the database and from where, hampering detection and investigation of unauthorized access attempts.

## Summary
This check fails when a `google_sql_database_instance` running PostgreSQL does not have the `log_connections` database flag explicitly set to `on`, meaning successful connection attempts to the database are not being logged.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `POSTGRES`
- **Check type:** resource check

## Why it matters
`log_connections` records every successful connection to the PostgreSQL instance, including the connecting user, database, and source. Without it, there is no audit trail of who (or what) connected and when, which is essential for detecting unauthorized access, investigating a suspected compromise, and satisfying compliance frameworks (PCI-DSS, HIPAA, SOC 2, CIS benchmarks) that require connection auditing on data stores. In an incident-response scenario, the absence of connection logs means responders cannot reconstruct the timeline of who accessed the database before/during a breach.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogConnection`) only evaluates PostgreSQL instances (`database_version` contains `POSTGRES`). It inspects `settings[0].database_flags` for a `log_connections` entry:
- **PASS** only if a flag with `name == "log_connections"` and `value == "on"` is found (must be explicit).
- **FAIL** if absent or set to any other value.
- **UNKNOWN** if not a PostgreSQL instance.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"
    # log_connections not configured
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_connections"
      value = "on"
    }
  }
}
```

## Remediation steps
1. Add a `database_flags` block with `name = "log_connections"` and `value = "on"` to the instance's `settings`.
2. If other `database_flags` entries already exist, add this as an additional block (Terraform allows repeated `database_flags` blocks) rather than replacing them.
3. Apply via `terraform apply`.
4. Ensure Cloud Logging export/log sinks are in place so connection logs are retained for the required audit period.
5. Re-scan with Checkov to confirm the flag is now explicitly `on`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogConnection.py)
- [GCP Cloud SQL: Configure PostgreSQL database flags](https://cloud.google.com/sql/docs/postgres/flags)
