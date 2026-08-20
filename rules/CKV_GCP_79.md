# CKV_GCP_79: Ensure SQL database is using latest Major version
## Severity
**LOW** (score: 2.0/10)

Running an unsupported major database engine version means any future disclosed CVE, including privilege-escalation or RCE bugs in the engine itself, will never be patched, leaving a sensitive structured-data store permanently exposed.

## Summary
This check ensures a `google_sql_database_instance` is running on a current, supported major database engine version rather than an outdated one that no longer receives security patches.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_sql_database_instance`

## Why it matters
Database engines regularly reach end-of-life for a given major version, after which the vendor (PostgreSQL, MySQL, SQL Server) stops issuing security patches for newly discovered CVEs. Running Cloud SQL on an outdated major version means any vulnerability disclosed after end-of-life support — including privilege escalation, remote code execution, or data-exposure bugs in the database engine itself — will never be patched by Google or upstream, leaving the instance permanently exposed. Since Cloud SQL instances typically hold an organization's most sensitive structured data, running an unsupported major version is a direct, unmitigated risk rather than a theoretical one.

## How Checkov evaluates this
Checkov reads the `database_version` attribute on `google_sql_database_instance` and checks it against an explicit allow-list of "latest" versions maintained by the check: `POSTGRES_18`, `MYSQL_8_0`, `MYSQL_8_4`, `SQLSERVER_2022_STANDARD`, `SQLSERVER_2022_WEB`, `SQLSERVER_2022_ENTERPRISE`, `SQLSERVER_2022_EXPRESS`. Any `database_version` value not in this list FAILS. Note: because this list is hardcoded per Checkov release, it can lag behind Google's actual currently-supported set — always cross-check against Google's current Cloud SQL version support matrix rather than treating a Checkov PASS as sufficient proof of currency.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "app-db"
  database_version = "POSTGRES_11"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "master" {
  name             = "app-db"
  database_version = "POSTGRES_18"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"
  }
}
```

## Remediation steps
1. Check Google's current Cloud SQL supported-versions documentation to confirm the true latest supported major version for your engine (PostgreSQL, MySQL, or SQL Server), since the check's hardcoded list may not reflect the newest release at any given time.
2. Plan and test a major-version upgrade path — for Cloud SQL this typically requires an in-place major version upgrade (where supported) or a dump/restore migration; verify application compatibility with the target major version first (breaking changes, deprecated syntax, extension/plugin support).
3. Update `database_version` in Terraform to the validated target version.
4. Note: changing `database_version` to a different major version may force resource replacement depending on the engine and provider version — always run `terraform plan` and review carefully before applying to a production instance; take a backup/export first regardless.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudSqlMajorVersion.py)
- [Google Cloud: Cloud SQL supported database versions](https://cloud.google.com/sql/docs/db-versions)
