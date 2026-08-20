# CKV_GCP_57: Ensure PostgreSQL database 'log_min_duration_statement' flag is set to '-1'

## Severity
**LOW** (score: 2.0/10)

Disabling statement-duration logging (log_min_duration_statement = -1) prevents full SQL statement text, which can include bind parameters such as passwords or tokens, from being written into database logs where it could later leak or be exfiltrated.

## Summary
This check fails when a `google_sql_database_instance` running PostgreSQL has the `log_min_duration_statement` database flag set to any value other than `-1`, which is Checkov's proxy for "not left at the safe default," since this flag (when set to a low positive threshold) causes full SQL statement text — potentially including literal parameter values such as passwords or PII — to be written to logs.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `POSTGRES`
- **Check type:** resource check

## Why it matters
`log_min_duration_statement` logs the duration and full text of any SQL statement that runs longer than the configured threshold (in milliseconds). While useful for performance tuning, logging full statement text is a data-exposure risk: queries frequently contain literal values passed as parameters — including credentials, tokens, or personally identifiable information — that then get written into the database log in plaintext. Log files typically have broader read access (or get shipped to less-restricted log aggregation systems) than the database itself, so enabling verbose statement logging can inadvertently create a secondary, less-protected copy of sensitive data. Checkov's baseline recommendation here is `-1` (disabled) specifically to avoid this data-leakage-via-logs vector; teams needing slow-query analysis should use narrower, more controlled mechanisms (e.g., `pg_stat_statements`) instead.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogMinDuration`) only evaluates PostgreSQL instances. It inspects `settings[0].database_flags` for `log_min_duration_statement`:
- **FAIL** if a `database_flags` entry has `name == "log_min_duration_statement"` and `value != "-1"`.
- **PASS** if the flag is absent, or explicitly set to `"-1"` (disabled).
- **UNKNOWN** if not a PostgreSQL instance.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_min_duration_statement"
      value = "500"  # logs full statement text for anything over 500ms
    }
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
      name  = "log_min_duration_statement"
      value = "-1"  # disabled — no full statement text logged
    }
  }
}
```

## Remediation steps
1. Set `log_min_duration_statement` to `"-1"` to disable full-statement duration logging.
2. If slow-query analysis is genuinely required, use `pg_stat_statements` (which tracks normalized query shapes and execution stats without exposing literal parameter values) instead of raising this flag.
3. If statement-level logging must be temporarily enabled for debugging, treat resulting logs as sensitive: restrict access, avoid forwarding to broadly-readable sinks, and disable again afterward.
4. Apply via `terraform apply` and re-scan with Checkov.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogMinDuration.py)
- [GCP Cloud SQL: Configure PostgreSQL database flags](https://cloud.google.com/sql/docs/postgres/flags)
