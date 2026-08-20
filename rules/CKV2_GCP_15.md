# CKV2_GCP_15: Ensure PostgreSQL database flag 'log_parser_stats' is set to 'off'
## Severity
**LOW** (score: 2.0/10)

log_parser_stats is a verbose PostgreSQL profiling flag whose recommended 'off' state is primarily a performance/log-hygiene best practice, with only marginal security value from avoiding excess internal detail in logs.

## Summary
This check ensures that Cloud SQL PostgreSQL instances do not have the `log_parser_stats` database flag turned on, since it is a debugging feature that adds parsing-stage profiling overhead and should stay disabled in normal operation.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform, specifically the `google_sql_database_instance` resource, and only when `database_version` indicates a PostgreSQL engine.

## Why it matters
`log_parser_stats` instructs PostgreSQL to collect and log detailed performance statistics for the query-parsing stage of execution. Like the other `log_*_stats` flags, it is intended only for short, targeted performance debugging sessions. Leaving it enabled in production adds continuous CPU/IO overhead to every parsed query and generates a large volume of verbose statistics entries in the database log. This degrades database performance under sustained load and inflates log volume, which increases log storage/ingestion cost and can bury genuinely important log entries (errors, auth failures, slow queries) in noise — making real operational and security issues harder to spot in the log stream.

## How Checkov evaluates this
An `or` of three `attribute` conditions on `google_sql_database_instance` — PASS if any hold:
1. `database_version` does **not** contain `"POSTGRES"`.
2. `settings.database_flags[*]` does not exist — no flags configured.
3. JSONPath `settings.database_flags[?(@.name == log_parser_stats & @.value == on)]` does not exist.

FAIL only when a PostgreSQL instance has a `database_flags` entry with `name = "log_parser_stats"` and `value = "on"`.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_parser_stats"
      value = "on"
    }
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_parser_stats"
      value = "off"
    }
  }
}
```

## Remediation steps
1. Set `log_parser_stats` to `"off"` or remove it from `database_flags` (PostgreSQL's default is off).
2. If parser-level profiling is genuinely needed, enable it only for a scoped, temporary debugging session (e.g. a session-level `SET`), not as a persistent instance flag.
3. Use `pg_stat_statements` or Cloud SQL Query Insights for ongoing, low-overhead production query performance visibility instead.
4. Changing Cloud SQL flags typically triggers an instance restart — plan a maintenance window.
5. Re-run Checkov / `terraform plan` to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPPostgreSQLDatabaseFlaglog_parser_statsIsSetToOFF.json
- GCP docs: https://cloud.google.com/sql/docs/postgres/flags
