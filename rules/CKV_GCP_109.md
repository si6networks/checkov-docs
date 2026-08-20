# CKV_GCP_109: Ensure the GCP PostgreSQL database log levels are set to ERROR or lower

## Severity
**LOW** (score: 2.0/10)

This setting tunes log verbosity for error-level statements to aid troubleshooting and forensics, but its absence does not itself open an exploitable attack path.

## Summary
This check ensures that a Cloud SQL PostgreSQL instance's `log_min_error_statement` database flag is set to a level of `error` or more verbose (e.g., `debug5`...`warning`, `error`), so that at minimum, statements causing errors are logged.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource type**: `google_sql_database_instance` (PostgreSQL engine)
- **Attribute inspected**: a `database_flags` block with `name = "log_min_error_statement"` whose `value` is one of `debug5, debug4, debug3, debug2, debug1, info, notice, warning, error`

## Why it matters
`log_min_error_statement` controls the minimum severity of SQL statement that PostgreSQL will log alongside its error message. If this flag is left at PostgreSQL's default (`panic`, meaning only near-fatal conditions get the offending statement logged) or set too high (e.g., `panic`, `fatal`), then most application/runtime errors — including errors caused by SQL injection attempts, permission-denied errors from unauthorized access attempts, or constraint violations from malicious input — will produce an error message without the statement text that caused it:

- **Loss of injection-attempt evidence**: A malformed or malicious query that fails (e.g., a SQL injection probe that produces a syntax error) is exactly the kind of event you want the full statement text logged for; without `log_min_error_statement` at `error` or lower, you'd see "an error occurred" without knowing what query triggered it.
- **Harder root-cause analysis of failures**: Both security investigations and routine operational debugging suffer when error logs lack the actual statement that failed, forcing responders to reproduce issues rather than read them directly from logs.
- **Compliance/audit trail weakness**: Demonstrating due diligence over database security often requires being able to show what was actually attempted against the database when incidents occur — this flag directly controls whether that evidence exists at all.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogMinErrorStatement`) uses the shared `AbsGooglePostgresqlDatabaseFlags` base class with `FLAG_NAME = "log_min_error_statement"` and an allowed `FLAG_VALUES` list of `["debug5","debug4","debug3","debug2","debug1","info","notice","warning","error"]` (i.e., everything at or more verbose than `error`, excluding `log`, `fatal`, `panic`):
- **PASSES** if a `database_flags` entry has `name = "log_min_error_statement"` and `value` is one of the allowed (sufficiently verbose) levels.
- **FAILS** if the flag is absent, or set to a value not in that list (e.g., `log`, `fatal`, or `panic`, which are less verbose and would suppress statement logging for ordinary errors).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "data-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-4-16384"

    database_flags {
      name  = "log_min_error_statement"
      value = "panic"
    }
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
      name  = "log_min_error_statement"
      value = "error"
    }
  }
}
```

## Remediation steps
1. In `src/cloud/infra/terraform/simulations/modules/database/main.tf` and `src/cloud/infra/terraform/data/modules/postgresql/main.tf`, add or update a `database_flags` block with `name = "log_min_error_statement"` and `value = "error"` (the minimal compliant, lowest-verbosity setting; more verbose values also pass but increase log volume).
2. If existing `database_flags` blocks are present for other settings (e.g., `log_hostname`, `cloudsql.enable_pgaudit`), add this as an additional flag rather than replacing them.
3. Changing this flag typically requires a Cloud SQL instance restart — schedule during a maintenance window.
4. Monitor log volume and storage/egress costs after the change, since more verbose levels (e.g., `debug1`) will significantly increase logged data compared to `error`; `error` is usually the right balance of security value vs. noise.
5. Re-scan with Checkov and confirm via `gcloud sql instances describe` that the flag is set to an accepted value.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogMinErrorStatement.py
- GCP Cloud SQL PostgreSQL flags documentation: https://cloud.google.com/sql/docs/postgres/flags
- PostgreSQL `log_min_error_statement` documentation: https://www.postgresql.org/docs/current/runtime-config-logging.html
