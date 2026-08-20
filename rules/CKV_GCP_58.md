# CKV_GCP_58: Ensure SQL database 'cross db ownership chaining' flag is set to 'off'

## Severity
**LOW** (score: 2.0/10)

SQL Server cross-database ownership chaining lets a user with access to one database implicitly reach objects in another database on the same instance without an explicit permission check, a well-known privilege-escalation and tenant-isolation-bypass risk on shared instances.

## Summary
This check fails when a `google_sql_database_instance` running SQL Server has the `cross db ownership chaining` database flag set to `on`, which allows ownership chains to span across databases within the instance.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `SQLSERVER`
- **Check type:** resource check

## Why it matters
SQL Server's cross-database ownership chaining lets a user access objects in a *different* database without an explicit permission check, as long as the accessing object and the target object share the same owner across both databases. When enabled instance-wide, this breaks the isolation boundary between databases hosted on the same Cloud SQL instance: a low-privilege user with access to one database can potentially reach objects (tables, stored procedures) in another database they were never explicitly granted access to, provided ownership conditions line up. This is a well-known SQL Server privilege-escalation and multi-tenancy-isolation risk, especially dangerous on shared instances hosting multiple applications or customers' databases. Microsoft and CIS both recommend leaving this off unless a specific, well-understood cross-database trust relationship is required.

## How Checkov evaluates this
The check (`GoogleCloudSqlServerCrossDBOwnershipChaining`) only evaluates SQL Server instances (`database_version` contains `SQLSERVER`). It inspects `settings[0].database_flags` for a flag named `cross db ownership chaining`:
- **FAIL** if a `database_flags` entry has `name == "cross db ownership chaining"` and `value == "on"`.
- **PASS** if the flag is absent, or set to any other value (e.g., `off`).
- **UNKNOWN** if not a SQL Server instance.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "sqlserver_instance" {
  name             = "app-sqlserver"
  database_version = "SQLSERVER_2019_STANDARD"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "cross db ownership chaining"
      value = "on"
    }
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "sqlserver_instance" {
  name             = "app-sqlserver"
  database_version = "SQLSERVER_2019_STANDARD"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "cross db ownership chaining"
      value = "off"
    }
  }
}
```

## Remediation steps
1. Set the `cross db ownership chaining` flag's `value` to `"off"` (or remove it, since off is the instance default).
2. If specific databases genuinely need to trust each other, use the per-database `DB CHAINING` option (`ALTER DATABASE ... SET DB_CHAINING ON`) scoped to just those databases rather than enabling it instance-wide.
3. Apply via `terraform apply`.
4. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudSqlServerCrossDBOwnershipChaining.py)
- [GCP Cloud SQL: Configure SQL Server database flags](https://cloud.google.com/sql/docs/sqlserver/flags)
