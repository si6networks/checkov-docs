# CKV_GCP_6: Ensure all Cloud SQL database instance requires all incoming connections to use SSL

## Severity
**HIGH** (score: 7.5/10)

Not requiring SSL/TLS for Cloud SQL connections allows database credentials and query data to be transmitted unencrypted, exposing them to interception on the network path.

## Summary
This check fails when a `google_sql_database_instance` does not enforce SSL/TLS-encrypted client connections, either via the modern `ssl_mode` setting or the legacy `require_ssl` boolean.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance`
- **Check type:** resource check

## Why it matters
Without enforced SSL/TLS, clients can connect to the Cloud SQL instance over plaintext, exposing all query traffic — including credentials embedded in connection strings, query parameters, and returned result-set data — to interception by anyone able to observe network traffic between the client and the instance (e.g., on a shared VPC, a misconfigured peering, or a compromised intermediate host). Since Cloud SQL instances are frequently reachable from multiple network paths (private IP, and sometimes public IP), failing to require SSL means the confidentiality and integrity of all database traffic depends entirely on client-side opt-in, which is unreliable in practice. Enforcing SSL at the instance level guarantees encryption in transit regardless of client configuration.

## How Checkov evaluates this
The check (`GoogleCloudSqlDatabaseRequireSsl`) inspects `settings[0].ip_configuration[0]` for either of two mutually-relevant attributes:
- If `ssl_mode` is present: **PASS** if its value is `TRUSTED_CLIENT_CERTIFICATE_REQUIRED` (or, for SQL Server instances specifically, `ENCRYPTED_ONLY`, since SQL Server doesn't support the client-certificate mode). Any other value → **FAIL**.
- Else if `require_ssl` is present (legacy field): **PASS** if `require_ssl` is truthy; **FAIL** if falsy.
- If neither attribute is set at all: **FAIL** (SSL is not enforced by default).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    ip_configuration {
      ipv4_enabled = false
      # no ssl_mode / require_ssl set — SSL not enforced
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

    ip_configuration {
      ipv4_enabled = false
      ssl_mode     = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }
  }
}
```

## Remediation steps
1. Add `ssl_mode = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"` inside the `ip_configuration` block for MySQL/PostgreSQL instances, or `ssl_mode = "ENCRYPTED_ONLY"` for SQL Server instances (since SQL Server does not support the trusted-client-cert mode).
2. If using an older provider version without `ssl_mode` support, set `require_ssl = true` instead (legacy field, being deprecated in favor of `ssl_mode`).
3. Distribute client SSL certificates (`google_sql_ssl_cert`) or configure clients to use Cloud SQL Auth Proxy / Cloud SQL Connectors, which handle mTLS automatically without requiring manual certificate management.
4. Apply with `terraform apply` — note this can briefly interrupt connections for clients not yet configured for SSL, so coordinate a rollout window.
5. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudSqlDatabaseRequireSsl.py)
- [GCP Cloud SQL: Configure SSL/TLS connections](https://cloud.google.com/sql/docs/postgres/configure-ssl-instance)
