# CKV2_GCP_13: Ensure PostgreSQL database flag 'log_duration' is set to 'on'
## Severity
**LOW** (score: 2.0/10)

Disabling log_duration on a Cloud SQL PostgreSQL instance removes query-timing data from logs, weakening the ability to detect abnormal or malicious query patterns (e.g. slow injection/enumeration attempts) after the fact.

## Summary
This check ensures that Cloud SQL PostgreSQL instances have the `log_duration` database flag explicitly turned on, so that the execution duration of every SQL statement is recorded in the database logs.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform, specifically the `google_sql_database_instance` resource, and only when `database_version` indicates a PostgreSQL engine.

## Why it matters
`log_duration` records how long each SQL statement took to execute. Unlike the other `log_*_stats` flags (which are noisy, high-overhead debugging aids that should stay off), `log_duration` is a low-overhead, security- and reliability-relevant control that this check wants turned **on**. Without duration logging, you lose visibility into anomalous database behavior: unusually long-running queries that could indicate a denial-of-service condition, a runaway/inefficient query degrading the whole instance, or — combined with statement logging — a slow query being used as part of a blind SQL injection / timing-based data-exfiltration attack. During incident response, the absence of duration data means investigators cannot correlate performance anomalies with a security event timeline, materially slowing detection and root-cause analysis.

## How Checkov evaluates this
An `or` of two `attribute` conditions on `google_sql_database_instance` — PASS if either holds:
1. `database_version` does **not** contain `"POSTGRES"` — not applicable to non-Postgres engines.
2. JSONPath `settings.database_flags[?(@.name == log_duration & @.value == on)]` **exists** — there's a flag entry named `log_duration` with value `on`.

FAIL when the instance is PostgreSQL and no `database_flags` entry sets `log_duration` to `on` (i.e. it's absent, or set to `off`).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"
    # No log_duration flag set -> defaults to off
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
      name  = "log_duration"
      value = "on"
    }
  }
}
```

## Remediation steps
1. Add a `database_flags` block with `name = "log_duration"` and `value = "on"` to both affected `google_sql_database_instance` resources (`simulations/modules/database/main.tf` and `data/modules/postgresql/main.tf`).
2. Ensure logs are shipped to Cloud Logging (default for Cloud SQL) and retained long enough to support incident investigation and compliance requirements.
3. Consider pairing with `log_min_duration_statement` for a threshold-based approach if full statement-duration logging on every query is too high-volume for your workload — but note `log_duration` alone (without statement text) is comparatively low-overhead and is what this check specifically requires.
4. Changing Cloud SQL database flags typically requires an instance restart — plan a maintenance window.
5. Re-run Checkov / `terraform plan` to confirm the finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPPostgreSQLDatabaseFlaglog_durationIsSetToON.json
- GCP docs: https://cloud.google.com/sql/docs/postgres/flags
