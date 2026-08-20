# CKV2_GCP_14: Ensure PostgreSQL database flag 'log_executor_stats' is set to 'off'
## Severity
**LOW** (score: 2.0/10)

log_executor_stats is a verbose PostgreSQL profiling flag whose recommended 'off' state is primarily a performance/log-hygiene best practice, with only marginal security value from avoiding excess internal detail in logs.

## Summary
This check ensures that Cloud SQL PostgreSQL instances do not have the `log_executor_stats` database flag turned on, since it is a debugging feature that adds overhead and noise and should stay disabled in normal operation.

## Applicability
Applies to Terraform, specifically the `google_sql_database_instance` resource, and only when `database_version` indicates a PostgreSQL engine.

## Why it matters
`log_executor_stats` is a PostgreSQL developer/debugging flag that emits detailed per-query executor performance statistics into the PostgreSQL log. Enabling it in production has two real costs: (1) a measurable performance/IO overhead from the extra profiling instrumentation on every executed statement, which can degrade database throughput and latency under load, and (2) significant log noise and volume growth, which can obscure genuinely important security/audit log entries (e.g. authentication failures, permission errors) and increase log storage/ingestion costs. This flag is meant for targeted performance troubleshooting sessions, not always-on production use — leaving it enabled is a reliability/operational-hygiene risk more than a direct confidentiality risk, but bloated/noisy logs also make it harder to detect actual security-relevant events.

## How Checkov evaluates this
This is an `or` of three `attribute` conditions on `google_sql_database_instance` — the check PASSes if any hold:
1. `database_version` does **not** contain `"POSTGRES"` — not a PostgreSQL instance, so the flag is inapplicable.
2. `settings.database_flags[*]` does not exist (`jsonpath_not_exists`) — no flags configured at all.
3. A JSONPath query `settings.database_flags[?(@.name == log_executor_stats & @.value == on)]` does **not** exist — meaning there is no flag entry with name `log_executor_stats` set to `on`.

The check FAILs only for a PostgreSQL instance whose `database_flags` list explicitly contains an entry with `name = "log_executor_stats"` and `value = "on"`.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_executor_stats"
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
      name  = "log_executor_stats"
      value = "off"
    }
  }
}
```

## Remediation steps
1. Set the `log_executor_stats` database flag to `"off"` explicitly, or remove it from `database_flags` entirely (the PostgreSQL default is off).
2. If executor-level profiling is needed, enable it temporarily and narrowly (e.g. via a session-level `SET` for a specific troubleshooting connection) rather than as an always-on instance flag.
3. For ongoing query performance visibility, use `pg_stat_statements` or Cloud SQL Insights instead, which are designed for continuous production monitoring with much lower overhead.
4. Note that changing Cloud SQL database flags typically requires an instance restart — plan for a maintenance window.
5. Re-run Checkov / `terraform plan` to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPPostgreSQLDatabaseFlaglog_executor_statsIsSetToOFF.json
- GCP docs: https://cloud.google.com/sql/docs/postgres/flags
