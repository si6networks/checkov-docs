# CKV_GCP_51: Ensure PostgreSQL database 'log_checkpoints' flag is set to 'on'

## Severity
**LOW** (score: 2.0/10)

log_checkpoints logging is primarily an operational/diagnostic aid for I/O and performance troubleshooting rather than a control that closes an actual attack path.

## Summary
This check fails when a `google_sql_database_instance` running PostgreSQL does not have the `log_checkpoints` database flag explicitly set to `on`, meaning checkpoint activity (a key indicator of I/O load and potential DoS/performance issues) is not being logged.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `POSTGRES`
- **Check type:** resource check

## Why it matters
PostgreSQL checkpoints flush dirty buffers to disk and are a major source of I/O spikes and latency. Logging checkpoint activity (`log_checkpoints = on`) records how often checkpoints occur, how long they take, and how much data they write. Without this logging, DBAs and security responders lose visibility into abnormal checkpoint frequency, which can be a symptom of a resource-exhaustion attack, runaway write workload, or misconfiguration causing performance degradation. This flag is part of the standard PostgreSQL/CIS audit-logging baseline used to establish a forensic trail for availability and performance incidents.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogCheckpoints`) only evaluates instances where `database_version` contains `POSTGRES`. It inspects `settings[0].database_flags` for an entry named `log_checkpoints`:
- **PASS** only if a `database_flags` entry has `name == "log_checkpoints"` and `value == "on"` (must be explicitly set).
- **FAIL** if the flag is absent, or present with any other value.
- **UNKNOWN** if the resource is not a PostgreSQL instance.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"
    # log_checkpoints not set — defaults to off in Cloud SQL
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
      name  = "log_checkpoints"
      value = "on"
    }
  }
}
```

## Remediation steps
1. Add (or fix) a `database_flags` block on the `google_sql_database_instance` resource with `name = "log_checkpoints"` and `value = "on"`.
2. Apply with `terraform apply` — Cloud SQL applies most PostgreSQL flag changes without a full restart, but verify in the [flags reference](https://cloud.google.com/sql/docs/postgres/flags).
3. Ensure logs are exported (e.g., to Cloud Logging / a log sink) so the checkpoint entries are actually retained and reviewable.
4. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogCheckpoints.py)
- [GCP Cloud SQL: Configure PostgreSQL database flags](https://cloud.google.com/sql/docs/postgres/flags)
