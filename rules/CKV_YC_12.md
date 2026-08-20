# CKV_YC_12: Ensure public IP is not assigned to database cluster

## Severity
**CRITICAL** (score: 9.0/10)

Assigning a public IP to a managed database host exposes a data-storing service directly to the internet, enabling unauthenticated network-level attacks against a sensitive backend.

## Summary
This check fails when a Yandex Managed Database cluster is configured to assign a public IP address to its hosts (or to the cluster, for Greenplum), making the database directly reachable from the internet.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `yandex_mdb_clickhouse_cluster`, `yandex_mdb_elasticsearch_cluster`, `yandex_mdb_greenplum_cluster`, `yandex_mdb_kafka_cluster`, `yandex_mdb_mongodb_cluster`, `yandex_mdb_mysql_cluster`, `yandex_mdb_postgresql_cluster`, `yandex_mdb_sqlserver_cluster`

## Why it matters
Managed database clusters are high-value targets: they hold the organization's most sensitive data. Assigning a public IP directly to a database host bypasses network-level isolation and exposes the database engine's listener port to the entire internet, where it can be discovered by automated scanners within minutes. Even with strong authentication, a directly internet-facing database is exposed to brute-force credential attacks, protocol-level exploits, and denial-of-service attempts, and it removes the network segmentation layer that would otherwise contain a compromised application server from directly pivoting to database data over a private path only. Databases should be reachable exclusively via private networking, with any legitimate external access mediated by a bastion host, VPN, or private endpoint.

## How Checkov evaluates this
The check (`MDBPublicIP`) is a `BaseResourceNegativeValueCheck` whose inspected attribute path depends on the resource type:
- For `yandex_mdb_kafka_cluster`: `config/[0]/assign_public_ip`
- For `yandex_mdb_greenplum_cluster`: `assign_public_ip`
- For all other supported cluster types: `host/[0]/assign_public_ip`
- The forbidden value is `[True]`.
- If the relevant `assign_public_ip` field is `true`, the check **FAILS**.
- If it is `false`, unset, or absent, the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_mdb_mysql_cluster" "example" {
  name        = "prod-mysql"
  environment = "PRODUCTION"
  network_id  = yandex_vpc_network.app.id
  version     = "8.0"

  resources {
    resource_preset_id = "s2.micro"
    disk_type_id        = "network-ssd"
    disk_size            = 20
  }

  host {
    zone             = "ru-central1-a"
    subnet_id        = yandex_vpc_subnet.app.id
    assign_public_ip = true  # public IP assigned -- FAILS CKV_YC_12
  }
}
```

## Remediated example
```hcl
resource "yandex_mdb_mysql_cluster" "example" {
  name        = "prod-mysql"
  environment = "PRODUCTION"
  network_id  = yandex_vpc_network.app.id
  version     = "8.0"

  resources {
    resource_preset_id = "s2.micro"
    disk_type_id        = "network-ssd"
    disk_size            = 20
  }

  host {
    zone             = "ru-central1-a"
    subnet_id        = yandex_vpc_subnet.app.id
    assign_public_ip = false  # no public IP -- PASSES CKV_YC_12
  }
}
```

## Remediation steps
1. Set `assign_public_ip = false` (or omit it, since it typically defaults to false) on each `host` block — or on `config` for Kafka, or the top-level attribute for Greenplum.
2. Ensure application servers connect to the cluster over the private VPC network, using the cluster's internal FQDN/IP.
3. If external access is required for administration or third-party tooling, use a bastion host, VPN gateway, or Yandex Cloud's private connectivity options instead.
4. Pair this with a restrictive `security_group_ids` configuration (see CKV_YC_1) so that even private-network access is scoped to necessary sources.
5. Disabling public IP assignment on an existing cluster host may require the host to be recreated or may trigger a brief connectivity interruption — plan a maintenance window.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/MDBPublicIP.py)
- [Yandex Managed Databases documentation](https://yandex.cloud/en/docs/managed-mysql/concepts/network)
