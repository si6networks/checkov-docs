# CKV_GCP_59: Ensure SQL database 'contained database authentication' flag is set to 'off'

## Severity
**LOW** (score: 2.0/10)

Contained database authentication lets users authenticate directly against a database without going through server-level login controls, bypassing centralized authentication policy and auditing and enabling access recovery even after the parent login is revoked.

## Summary
This check fails when a `google_sql_database_instance` running SQL Server has the `contained database authentication` database flag set to `on`, which permits users to authenticate directly to individual databases without a corresponding server-level login.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `SQLSERVER`
- **Check type:** resource check

## Why it matters
Contained databases allow user authentication and metadata to live inside the database itself rather than at the instance/server level. This is convenient for portability (moving a database between servers without recreating logins) but weakens centralized security control: server-level login auditing, password policies, and access reviews performed at the instance level can be bypassed because contained users authenticate straight into the database. This creates a shadow authentication path that security teams may not be monitoring, increases the attack surface for credential-based attacks, and makes it harder to enforce a consistent authentication/authorization model across all databases on an instance. It's flagged as a security-relevant setting in the CIS SQL Server benchmark for this reason — it should only be enabled deliberately, with the security implications understood, not left on by default.

## How Checkov evaluates this
The check (`GoogleCloudSqlServerContainedDBAuthentication`) only evaluates SQL Server instances. It inspects `settings[0].database_flags` for `contained database authentication`:
- **FAIL** if a `database_flags` entry has `name == "contained database authentication"` and `value == "on"`.
- **PASS** if the flag is absent, or set to any other value.
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
      name  = "contained database authentication"
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
      name  = "contained database authentication"
      value = "off"
    }
  }
}
```

## Remediation steps
1. Set the `contained database authentication` flag's `value` to `"off"` (or omit it, since off is the default).
2. If a specific application genuinely requires contained databases (e.g., for portability/DR scenarios), document the exception and enforce compensating controls: audit contained-user creation, enforce strong password policy on contained users, and monitor for unexpected contained-user logins.
3. Apply via `terraform apply`.
4. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudSqlServerContainedDBAuthentication.py)
- [GCP Cloud SQL: Configure SQL Server database flags](https://cloud.google.com/sql/docs/sqlserver/flags)
