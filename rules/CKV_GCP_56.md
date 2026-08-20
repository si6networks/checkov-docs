# CKV_GCP_56: Ensure PostgreSQL database 'log_temp_files' flag is set to '0'

## Severity
**LOW** (score: 2.0/10)

log_temp_files logging is a performance-diagnostic aid for tracking disk-based temp file usage, with minimal direct security exploitability.

## Summary
This check fails when a `google_sql_database_instance` running PostgreSQL has the `log_temp_files` database flag set to anything other than `0`, since a non-zero (or unset) value suppresses logging of temporary file usage that indicates queries spilling to disk.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `POSTGRES`
- **Check type:** resource check

## Why it matters
PostgreSQL creates temporary files on disk when a sort, hash, or other operation exceeds `work_mem`. Setting `log_temp_files = 0` logs the creation of **every** temp file regardless of size, giving full visibility into queries that are memory-starved or unusually expensive. This matters for both performance and security: an attacker attempting resource exhaustion (e.g., via crafted queries that force huge sorts/joins) or a runaway/poorly-written query can degrade database availability, and without full temp-file logging these events go unnoticed until the disk fills up or performance visibly collapses. Setting the threshold to any positive number (or leaving it unset) means only large temp files are logged, hiding a class of moderate-impact abuse or misbehavior.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogTemp`) only evaluates PostgreSQL instances. It inspects `settings[0].database_flags` for `log_temp_files`:
- **FAIL** if a `database_flags` entry has `name == "log_temp_files"` and `value != "0"`.
- **PASS** if the flag is absent, or explicitly set to `"0"`.
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
      name  = "log_temp_files"
      value = "1000"  # only logs temp files >= 1000 KB
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
      name  = "log_temp_files"
      value = "0"  # log all temp file creation, regardless of size
    }
  }
}
```

## Remediation steps
1. Set the `log_temp_files` flag's `value` to `"0"` (note: Checkov requires the flag be present and equal to `"0"`; the PostgreSQL default of `-1`, which disables logging entirely, will fail this check).
2. Apply via `terraform apply`.
3. Monitor log volume after enabling — on high-throughput instances this can be verbose; consider log-based metrics/alerts rather than manual review.
4. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogTemp.py)
- [GCP Cloud SQL: Configure PostgreSQL database flags](https://cloud.google.com/sql/docs/postgres/flags)
