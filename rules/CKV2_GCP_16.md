# CKV2_GCP_16: Ensure PostgreSQL database flag 'log_planner_stats' is set to 'off'
## Severity
**LOW** (score: 2.0/10)

log_planner_stats is a verbose PostgreSQL profiling flag whose recommended 'off' state is primarily a performance/log-hygiene best practice, with only marginal security value from avoiding excess internal detail in logs.

## Summary
This check ensures that Cloud SQL PostgreSQL instances do not have the `log_planner_stats` database flag turned on, since it is a debugging feature that adds query-planner profiling overhead and should stay disabled in normal operation.

## Applicability
Applies to Terraform, specifically the `google_sql_database_instance` resource, and only when `database_version` indicates a PostgreSQL engine.

## Why it matters
`log_planner_stats` causes PostgreSQL to record detailed performance statistics for the query-planning stage on every query. It is intended strictly for short-lived performance troubleshooting. Left enabled continuously, it imposes measurable CPU overhead on the query planner for every statement executed and floods the database log with verbose statistics, increasing storage/ingestion costs for logging pipelines and making it harder to spot genuinely important entries (errors, failed authentications, slow-query warnings) amid the noise — an operational-hygiene and observability risk more than a direct confidentiality one, but one that materially degrades incident detection and database performance at scale.

## How Checkov evaluates this
An `or` of three `attribute` conditions on `google_sql_database_instance` — PASS if any hold:
1. `database_version` does **not** contain `"POSTGRES"`.
2. `settings.database_flags[*]` does not exist.
3. JSONPath `settings.database_flags[?(@.name == log_planner_stats & @.value == on)]` does not exist.

FAIL only when a PostgreSQL instance has a `database_flags` entry with `name = "log_planner_stats"` and `value = "on"`.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_planner_stats"
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
      name  = "log_planner_stats"
      value = "off"
    }
  }
}
```

## Remediation steps
1. Set `log_planner_stats` to `"off"` or remove it from `database_flags` (PostgreSQL default is off).
2. If planner-level profiling is genuinely needed, enable it only for a short, targeted debugging session via a session-level `SET`, not as a persistent flag.
3. Use `pg_stat_statements` or Cloud SQL Query Insights for continuous production query performance monitoring instead.
4. Changing Cloud SQL flags typically requires an instance restart — plan a maintenance window.
5. Re-run Checkov / `terraform plan` to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPPostgreSQLDatabaseFlaglog_planner_statsIsSetToOFF.json
- GCP docs: https://cloud.google.com/sql/docs/postgres/flags
