# CKV_GCP_108: Ensure hostnames are logged for GCP PostgreSQL databases

## Severity
**LOW** (score: 2.0/10)

This flag only affects the granularity of forensic detail captured in connection logs and has no direct effect on the confidentiality, integrity, or availability of the database.

## Summary
This check ensures that a Cloud SQL PostgreSQL instance (`google_sql_database_instance`) has the `log_hostname` database flag set to `on`, so client hostnames are resolved and recorded in connection logs alongside IP addresses.

## Applicability
- **IaC framework**: Terraform
- **Resource type**: `google_sql_database_instance` (PostgreSQL engine)
- **Attribute inspected**: a `database_flags` block with `name = "log_hostname"` and `value = "on"`

## Why it matters
PostgreSQL's connection and audit logs record the source of each connection. By default, only the connecting IP address is logged; enabling `log_hostname` performs a reverse-DNS lookup and records the resolved hostname too. For the flagged database modules in this repo (a simulations database and a general PostgreSQL module), this directly affects incident-response capability:

- **Weaker forensic attribution**: When investigating a suspicious connection (unexpected access pattern, potential credential compromise, connection from an unfamiliar network), a raw IP address is often insufficient — DNS-resolvable hostnames (e.g., a known bastion host, CI runner, or VPN exit name) provide immediately actionable context, cutting investigation time significantly.
- **Harder correlation with other logs**: Many security tools and internal asset inventories key off hostnames rather than raw IPs, especially in dynamic cloud environments where IPs are frequently reassigned; without `log_hostname`, correlating a database connection with "which specific system connected" requires an extra, error-prone IP-to-asset lookup step performed after the fact (if IP-to-hostname mapping data is even still available by then).
- **Compliance logging requirements**: Some audit standards expect connection logs to capture sufficiently identifying information about the connecting client, not just an ephemeral IP.
- **Trade-off to be aware of**: Enabling `log_hostname` adds the overhead of a DNS lookup per connection, which can add latency under very high connection churn — this is a known, generally acceptable trade-off for the forensic value gained, but worth load-testing for extremely high-QPS instances.

## How Checkov evaluates this
The check (`GoogleCloudPostgreSqlLogHostname`) uses a shared base class (`AbsGooglePostgresqlDatabaseFlags`) parameterized with `FLAG_NAME = "log_hostname"` and `FLAG_VALUES = ["on"]`. It inspects the instance's `settings.database_flags` list, looking for an entry whose `name` equals `log_hostname`:
- **PASSES** if a `database_flags` entry has `name = "log_hostname"` and `value = "on"`.
- **FAILS** if the flag is absent entirely, or present with a value other than `"on"` (e.g., `"off"`).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "sim-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-4-16384"
    # No log_hostname flag set — defaults to off
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "sim-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-4-16384"

    database_flags {
      name  = "log_hostname"
      value = "on"
    }
  }
}
```

## Remediation steps
1. In `src/cloud/infra/terraform/simulations/modules/database/main.tf` and `src/cloud/infra/terraform/data/modules/postgresql/main.tf`, add a `database_flags` block with `name = "log_hostname"` and `value = "on"` inside `settings`.
2. If other `database_flags` entries already exist on the instance, add this as an additional block rather than replacing existing flags — Terraform's `google_sql_database_instance` allows multiple `database_flags` blocks.
3. Applying a database flag change on Cloud SQL typically requires an instance restart to take effect — coordinate with a maintenance window, especially for the shared `postgresql` module which may back multiple environments.
4. Monitor connection latency after enabling, particularly for high-throughput services, since `log_hostname` adds a reverse-DNS lookup cost per new connection.
5. Re-scan with Checkov and verify via `gcloud sql instances describe` that `log_hostname=on` is reflected in the instance's settings.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudPostgreSqlLogHostname.py
- GCP Cloud SQL PostgreSQL flags documentation: https://cloud.google.com/sql/docs/postgres/flags
- PostgreSQL `log_hostname` documentation: https://www.postgresql.org/docs/current/runtime-config-logging.html
