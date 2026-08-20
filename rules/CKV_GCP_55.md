# CKV_GCP_55: Ensure PostgreSQL database 'log_min_messages' flag is set to a valid value

## Severity
**LOW** (score: 2.0/10)

log_min_messages controls log verbosity thresholds for operational messages and is a hygiene/observability setting rather than a control over a concrete attack surface.

## Summary
This check fails when a `google_sql_database_instance` running PostgreSQL has a `log_min_messages` database flag set to a value outside the recognized severity levels, since an invalid or overly-restrictive setting silences important log output.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `POSTGRES`
- **Check type:** resource check

## Why it matters
`log_min_messages` controls the minimum severity of messages PostgreSQL writes to its server log (e.g., `debug5` through `info`, `notice`, `warning`, `error`, `log`, `fatal`, `panic`). If this is set to an invalid value, or set too high (e.g., only `panic`), routine and security-relevant events — failed statements, constraint violations, permission errors — never reach the log stream. Since log_min_messages is a component of the standard CIS PostgreSQL benchmark, and downstream logging pipelines (SIEMs, alerting) depend on these messages being emitted, a bad configuration here silently defeats database observability and incident-detection capability, without an obvious symptom in normal operation.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogMinMessage`) only evaluates PostgreSQL instances. It inspects `settings[0].database_flags` for `log_min_messages`, and compares its value against the valid PostgreSQL severity levels:

```python
logmin_list = ['fatal', 'panic', 'log', 'error', 'warning', 'notice',
               'info', 'debug1', 'debug2', 'debug3', 'debug4', 'debug5']
```

- **FAIL** if a `database_flags` entry has `name == "log_min_messages"` and its `value` is **not** in `logmin_list`.
- **PASS** if the flag is absent, or present with a value from the valid list.
- **UNKNOWN** if not a PostgreSQL instance.

Note this check only validates the value is a recognized level string — it does not enforce any particular minimum severity (e.g. it does not require `warning` or stricter).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "log_min_messages"
      value = "verbose"  # not a valid PostgreSQL severity level
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
      name  = "log_min_messages"
      value = "warning"  # a recognized severity level
    }
  }
}
```

## Remediation steps
1. Check the `log_min_messages` flag value against valid PostgreSQL severities: `debug5, debug4, debug3, debug2, debug1, info, notice, warning, error, log, fatal, panic`.
2. Correct any typo'd or invalid value; a common security baseline choice is `warning` or `error`.
3. Apply with `terraform apply`.
4. Verify the resulting log verbosity is compatible with your log ingestion volume/cost budget before rolling to production.
5. Re-scan with Checkov.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogMinMessage.py)
- [GCP Cloud SQL: Configure PostgreSQL database flags](https://cloud.google.com/sql/docs/postgres/flags)
