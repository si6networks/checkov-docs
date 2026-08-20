# CKV_GCP_54: Ensure PostgreSQL database 'log_lock_waits' flag is set to 'on'

## Severity
**LOW** (score: 2.0/10)

log_lock_waits is a performance/diagnostic setting for identifying lock contention and has little direct bearing on confidentiality, integrity, or exploitability.

## Summary
This check fails when a `google_sql_database_instance` running PostgreSQL does not have the `log_lock_waits` database flag explicitly set to `on`, meaning sessions that wait longer than `deadlock_timeout` for a lock are not logged.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `POSTGRES`
- **Check type:** resource check

## Why it matters
`log_lock_waits` logs any session that waits an unusually long time to acquire a lock (row, table, or advisory). Excessive lock waits are a common symptom of both application bugs (long transactions, missing indexes) and deliberate resource-exhaustion/DoS attacks against a database (e.g., a malicious or compromised client holding locks open to starve other transactions). Without this logging, operators have no early signal of lock contention building up, and security teams lose a data point useful for identifying an attacker deliberately stalling the database to cause a denial of service or to mask other malicious activity happening concurrently.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogLockWaits`) only evaluates PostgreSQL instances. It inspects `settings[0].database_flags` for `log_lock_waits`:
- **PASS** only if a flag `name == "log_lock_waits"` has `value == "on"` explicitly.
- **FAIL** if absent or any other value.
- **UNKNOWN** if not a PostgreSQL instance.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"
    # log_lock_waits not configured
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
      name  = "log_lock_waits"
      value = "on"
    }
  }
}
```

## Remediation steps
1. Add a `database_flags` block with `name = "log_lock_waits"` and `value = "on"` to the instance's `settings`.
2. Preserve any existing `database_flags` blocks — add this as an additional entry.
3. Apply via `terraform apply`.
4. Optionally tune `deadlock_timeout` alongside this flag if lock-wait logging is too noisy or not sensitive enough for your workload.
5. Re-scan with Checkov to confirm the flag is explicitly `on`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogLockWaits.py)
- [GCP Cloud SQL: Configure PostgreSQL database flags](https://cloud.google.com/sql/docs/postgres/flags)
