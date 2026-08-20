# CKV_GCP_53: Ensure PostgreSQL database 'log_disconnections' flag is set to 'on'

## Severity
**LOW** (score: 2.0/10)

Disabling disconnection logging weakens the session audit trail needed to reconstruct the timeline and duration of a database access event during an incident investigation.

## Summary
This check fails when a `google_sql_database_instance` running PostgreSQL does not have the `log_disconnections` database flag explicitly set to `on`, meaning session terminations from the database are not being logged.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `POSTGRES`
- **Check type:** resource check

## Why it matters
`log_disconnections` records when and how a session ended (normal termination, timeout, error) along with session duration. Paired with `log_connections`, it lets you reconstruct the full lifetime of every database session — essential for forensic timelines during an incident, for spotting abnormal session patterns (e.g., unusually short/long sessions indicative of automated exfiltration or brute-force activity), and for compliance regimes that mandate full session audit trails on data stores holding regulated data. Missing disconnection logs leave a gap that prevents correlating "session start" events with their corresponding end, undermining audit completeness.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogDisconnection`) only evaluates PostgreSQL instances. It inspects `settings[0].database_flags` for `log_disconnections`:
- **PASS** only if a flag `name == "log_disconnections"` has `value == "on"` explicitly.
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
    # log_disconnections not configured
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
      name  = "log_disconnections"
      value = "on"
    }
  }
}
```

## Remediation steps
1. Add a `database_flags` block with `name = "log_disconnections"` and `value = "on"` to the instance's `settings`.
2. Keep any existing `database_flags` blocks (e.g. `log_connections`, `log_checkpoints`) — add this as an additional block rather than replacing them.
3. Apply via `terraform apply`.
4. Confirm logs are shipped to Cloud Logging with adequate retention for audit/compliance needs.
5. Re-scan with Checkov to verify the flag is explicitly `on`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogDisconnection.py)
- [GCP Cloud SQL: Configure PostgreSQL database flags](https://cloud.google.com/sql/docs/postgres/flags)
