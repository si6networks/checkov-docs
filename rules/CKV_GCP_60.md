# CKV_GCP_60: Ensure Cloud SQL database does not have public IP

## Severity
**HIGH** (score: 8.0/10)

Assigning a Cloud SQL instance a public IP puts a data store directly on the internet, making it discoverable by scanners and reliant entirely on authorized-network allowlist hygiene to avoid unauthorized access or brute-force attacks.

## Summary
This check fails when a `google_sql_database_instance` has `ipv4_enabled = true` in its `ip_configuration`, meaning the instance is assigned a publicly routable IPv4 address.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_sql_database_instance`
- **Check type:** resource check

## Why it matters
A Cloud SQL instance with a public IP is directly reachable from the internet, subject only to whatever authorized-networks/firewall rules are configured — and misconfigurations (an overly broad `0.0.0.0/0` authorized network, or none at all leaving the endpoint exposed to credential-based attacks) are a common real-world cause of database breaches. Even with authorized networks correctly restricted, a public IP increases the attack surface: it's discoverable via internet-wide scanning, subject to brute-force login attempts, and depends entirely on IP allowlist hygiene remaining correct forever. Using only a private IP (requiring VPC peering or Private Service Connect) removes the instance from internet reachability entirely, which is a fundamentally stronger security posture than relying on IP allowlisting alone.

## How Checkov evaluates this
The check (`GoogleCloudSqlServerNoPublicIP`) inspects `settings[0].ip_configuration[0].ipv4_enabled`:
- **FAIL** if `ipv4_enabled` is present and truthy.
- **PASS** otherwise (i.e., `ipv4_enabled` is absent, or explicitly `false`).

Note: the default value of `ipv4_enabled` in the Google provider is actually `true`, so simply omitting `ip_configuration` entirely (using the API/provider default) results in a public IP being assigned — this check's PASS logic on "attribute absent" reflects only what's visible in the Terraform config, not the live default; always set it explicitly.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "pg_instance" {
  name             = "app-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-8192"

    ip_configuration {
      ipv4_enabled = true
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
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]
}
```

## Remediation steps
1. Set `ipv4_enabled = false` in the instance's `ip_configuration` block.
2. Configure `private_network` pointing to a VPC, and set up the required `google_service_networking_connection` (VPC peering) for Cloud SQL private services access — this must exist before the instance can attach a private IP.
3. Update all clients (application servers, Cloud Functions with a VPC connector, etc.) to connect via the private IP or Cloud SQL Auth Proxy over the private network.
4. Note: disabling the public IP on an existing instance is disruptive to any client currently connecting over the public IP — plan a migration window and update connection strings/VPC connectivity first.
5. Re-scan with Checkov to confirm compliance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudSqlServerNoPublicIP.py)
- [GCP Cloud SQL: Configure private IP](https://cloud.google.com/sql/docs/mysql/configure-private-ip)
