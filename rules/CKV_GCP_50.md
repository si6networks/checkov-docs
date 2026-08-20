# CKV_GCP_50: Ensure MySQL database 'local_infile' flag is set to 'off'

## Severity
**LOW** (score: 2.0/10)

Leaving MySQL's local_infile flag on allows LOAD DATA LOCAL INFILE, which combined with SQL injection or a compromised client can be used to read arbitrary local files or, in some configurations, write files back to the server.

## Summary
This check fails when a `google_sql_database_instance` running MySQL has the `local_infile` database flag explicitly set to `on`, since this flag enables client-side `LOAD DATA LOCAL INFILE` which can be abused to read arbitrary local files.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance` where `database_version` contains `MYSQL`
- **Check type:** resource check

## Why it matters
The MySQL `local_infile` setting controls whether `LOAD DATA LOCAL INFILE` statements are permitted. When enabled, a client (or an application vulnerable to SQL injection) can instruct the MySQL client library to read a file from the **client/application host's local filesystem** and load it into a table — or, in malicious-server scenarios, a compromised/rogue MySQL server can request arbitrary local files from a connecting client. This has been used in real-world attacks to exfiltrate sensitive files (e.g., `/etc/passwd`, application config files, SSH keys) from an app server through a SQL injection flaw that would otherwise be limited to database-only impact. Disabling `local_infile` removes this whole class of local-file-disclosure attack via the MySQL protocol.

## How Checkov evaluates this
The check (`GoogleCloudMySqlLocalInfileOff`) only evaluates instances where `database_version` contains `MYSQL`. It then looks at `settings[0].database_flags` for a flag named `local_infile`:
- **FAIL** if a `database_flags` entry has `name == "local_infile"` and `value == "on"`.
- **PASS** if no such flag is present (default is off) or if it's explicitly set to any other value (e.g., `off`).
- **UNKNOWN** (not evaluated) if the resource isn't a MySQL instance.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "mysql_instance" {
  name             = "app-mysql"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "local_infile"
      value = "on"
    }
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "mysql_instance" {
  name             = "app-mysql"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    database_flags {
      name  = "local_infile"
      value = "off"   # or simply omit the flag entirely
    }
  }
}
```

## Remediation steps
1. Locate the `database_flags` block in the affected `google_sql_database_instance` resource.
2. Remove the `local_infile` flag entirely, or set its `value` to `"off"`.
3. If application code relies on `LOAD DATA LOCAL INFILE` for bulk imports, migrate to server-side `LOAD DATA INFILE` from Cloud Storage, or use Cloud SQL's import mechanisms instead.
4. Apply the change with `terraform apply` — this is an in-place flag update and does not require instance replacement, but Cloud SQL will restart the instance to apply some flag changes; check the [flag reference](https://cloud.google.com/sql/docs/mysql/flags) for whether a restart is required.
5. Re-scan with Checkov to confirm the instance passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudMySqlLocalInfileOff.py)
- [GCP Cloud SQL: Configure database flags](https://cloud.google.com/sql/docs/mysql/flags)
