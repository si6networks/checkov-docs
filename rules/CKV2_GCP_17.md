# CKV2_GCP_17: Ensure PostgreSQL database flag 'log_statement_stats' is set to 'off'
## Severity
**LOW** (score: 2.0/10)

log_statement_stats is a verbose PostgreSQL profiling flag whose recommended 'off' state is primarily a performance/log-hygiene best practice, with only marginal security value from avoiding excess internal detail in logs.

## Summary
This check ensures that Cloud SQL PostgreSQL instances do not have the `log_statement_stats` database flag turned on, since it is a debugging feature that adds end-to-end statement profiling overhead and should stay disabled in normal operation.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform, specifically the `google_sql_database_instance` resource, and only when `database_version` indicates a PostgreSQL engine.

## Why it matters
`log_statement_stats` causes PostgreSQL to log combined end-to-end performance statistics (parser + planner + executor) for every statement. Because it aggregates all the sub-stage stats, it carries even more overhead than the individual `log_parser_stats`/`log_planner_stats`/`log_executor_stats` flags, and PostgreSQL's own documentation notes it cannot be enabled together with the other per-stage stats flags. Running it continuously in production measurably slows query processing and produces a very high volume of log output, inflating log storage/ingestion costs and making it substantially harder to find security- and reliability-relevant log entries (authentication failures, errors, slow queries) in the resulting noise.

## How Checkov evaluates this
An `or` of three `attribute` conditions on `google_sql_database_instance` — PASS if any hold:
1. `database_version` does **not** contain `"POSTGRES"`.
2. `settings.database_flags[*]` does not exist.
3. JSONPath `settings.database_flags[?(@.name == log_statement_stats & @.value == on)]` does not exist.

FAIL only when a PostgreSQL instance has a `database_flags` entry with `name = "log_statement_stats"` and `value = "on"`.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_statement_stats"
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
      name  = "log_statement_stats"
      value = "off"
    }
  }
}
```

## Remediation steps
1. Set `log_statement_stats` to `"off"` or remove it from `database_flags` (PostgreSQL default is off).
2. If full-statement profiling is genuinely needed, enable it only briefly and scoped to a single debugging session (e.g. via a session-level `SET`), never as an always-on production flag.
3. Use `pg_stat_statements` or Cloud SQL Query Insights for continuous, low-overhead production query performance visibility instead.
4. Changing Cloud SQL flags typically requires an instance restart — plan a maintenance window.
5. Re-run Checkov / `terraform plan` to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPPostgreSQLDatabaseFlaglog_statement_statsIsSetToOFF.json
- GCP docs: https://cloud.google.com/sql/docs/postgres/flags
