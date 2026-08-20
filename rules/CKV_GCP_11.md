# CKV_GCP_11: Ensure that Cloud SQL database Instances are not open to the world

## Severity
**CRITICAL** (score: 9.0/10)

A Cloud SQL instance configured to accept connections from 0.0.0.0/0 exposes the database directly to internet-wide brute-force attempts and exploitation of any database-layer vulnerability.

## Summary
This check ensures that a `google_sql_database_instance`'s authorized networks (both static entries and `dynamic "authorized_networks"` blocks) do not include a CIDR range ending in `/0` (i.e., `0.0.0.0/0`), which would allow any IP address on the internet to attempt a connection to the database.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource type**: `google_sql_database_instance`
- Specifically inspects the `settings.ip_configuration.authorized_networks` (static list) and `settings.ip_configuration.dynamic.authorized_networks` (dynamic block) attributes.

## Why it matters
Cloud SQL's `authorized_networks` list controls which source IP ranges are allowed to reach the instance's public IP directly (independent of firewall rules on VPC-native resources, since Cloud SQL public IP access is gated at the Cloud SQL layer itself). Authorizing `0.0.0.0/0`:

- **Exposes the database directly to internet-wide scanning and brute force**: Any host on the internet can attempt TCP connections to the database's public IP and attempt authentication, turning credential strength and patch level into the only remaining defenses — a single weak/leaked password or an unpatched MySQL/PostgreSQL CVE becomes directly exploitable from anywhere.
- **Removes network segmentation as a defense layer**: Best practice for datastores is defense in depth — VPC-only or Cloud SQL Auth Proxy/Private IP access plus authentication. Opening to `0.0.0.0/0` collapses network-layer protection entirely, relying solely on the database's own auth.
- **Amplifies impact of credential leakage**: If application credentials are ever leaked (e.g., in a public repo, a misconfigured log, or a compromised CI pipeline), a `0.0.0.0/0`-authorized database is immediately reachable and exploitable by whoever obtains those credentials, with no additional network barrier to slow them down.
- **Compliance violations**: PCI-DSS, HIPAA, and most cloud security benchmarks explicitly prohibit database instances with unrestricted public network access.

## How Checkov evaluates this
The check (`GoogleCloudSqlDatabasePubliclyAccessible`) inspects `settings[0].ip_configuration[0]`:
1. If `authorized_networks` is present (as a list or a single legacy-format entry), it iterates each network entry's `value` (the CIDR string) and **FAILS** if any value ends with `/0`.
2. It separately checks `ip_configuration[0].dynamic` blocks — for each `dynamic "authorized_networks"` block's `content`, it **FAILS** if the resolved `value` ends with `/0`.
3. If no `/0`-ending value is found in either the static list or dynamic blocks, it **PASSES**.
4. If `ip_configuration` is absent from `settings` entirely, the check has no data to evaluate against and effectively passes (no explicit unrestricted network is declared).

## Non-compliant example
```hcl
resource "google_sql_database_instance" "main" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "everyone"
        value = "0.0.0.0/0"
      }
    }
  }
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "main" {
  name             = "app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id

      authorized_networks {
        name  = "office-vpn"
        value = "203.0.113.10/32"
      }
    }
  }
}
```

## Remediation steps
1. Remove any `authorized_networks` entry (static or in a `dynamic` block) whose CIDR ends in `/0`.
2. Replace unrestricted access with specific, narrow CIDR ranges for the known source IPs that legitimately need public access (office IPs, bastion hosts, specific NAT gateway egress IPs), or eliminate public IP access entirely.
3. Prefer disabling `ipv4_enabled` and using `private_network` (Private Service Access / Private IP) so the database is only reachable from within your VPC.
4. For application connectivity, use the Cloud SQL Auth Proxy or Private Service Connect instead of exposing a public IP at all.
5. Applying this change does not require instance downtime for the authorized-networks update itself, but switching `ipv4_enabled` off/on can require connectivity cutover planning for connected applications.
6. Re-scan with Checkov and confirm no `/0` CIDR remains in either the static or dynamic authorized-networks configuration.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudSqlDatabasePubliclyAccessible.py
- GCP Cloud SQL authorized networks documentation: https://cloud.google.com/sql/docs/mysql/configure-ip
