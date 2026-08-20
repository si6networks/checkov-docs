# CKV_YC_1: Ensure security group is assigned to database cluster

## Severity
**HIGH** (score: 7.8/10)

A managed database cluster with no security group assigned relies on default/open network ACLs, materially increasing the chance that data-plane ports are reachable from unintended sources.

## Summary
This check fails when a Yandex Managed Database cluster resource does not have a `security_group_ids` attribute set, meaning the cluster's network access is not governed by an explicit VPC security group.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_mdb_clickhouse_cluster`, `yandex_mdb_elasticsearch_cluster`, `yandex_mdb_greenplum_cluster`, `yandex_mdb_kafka_cluster`, `yandex_mdb_mongodb_cluster`, `yandex_mdb_mysql_cluster`, `yandex_mdb_postgresql_cluster`, `yandex_mdb_redis_cluster`, `yandex_mdb_sqlserver_cluster`

## Why it matters
Without a security group explicitly attached, a Yandex Managed Database cluster relies on default network ACL behavior, which in many configurations can allow broader network reachability than intended. Security groups in Yandex Cloud VPC act as stateful firewalls controlling which subnets/IP ranges/ports can reach the cluster's network interfaces. Omitting them removes a critical layer of network segmentation: any host that can otherwise route to the cluster's network could attempt connections, increasing exposure to brute-force login attempts, exploitation of database-engine vulnerabilities, and lateral movement in the event another system on the same network is compromised. Explicit security groups let you enforce least-privilege network access (e.g., only application subnets and bastion hosts can reach the database port).

## How Checkov evaluates this
The check (`MDBSecurityGroup`) is a `BaseResourceValueCheck` that inspects the `security_group_ids` attribute:
- The expected value is `ANY_VALUE` — meaning any non-empty value satisfies the check.
- If `security_group_ids` is set (to one or more security group IDs), the check **PASSES**.
- If the attribute is absent or empty, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_mdb_postgresql_cluster" "example" {
  name        = "prod-postgres"
  environment = "PRODUCTION"
  network_id  = yandex_vpc_network.app.id

  config {
    version = "15"
    resources {
      resource_preset_id = "s2.micro"
      disk_type_id        = "network-ssd"
      disk_size            = 20
    }
  }

  host {
    zone      = "ru-central1-a"
    subnet_id = yandex_vpc_subnet.app.id
  }
  # no security_group_ids set -- FAILS CKV_YC_1
}
```

## Remediated example
```hcl
resource "yandex_vpc_security_group" "db_sg" {
  name       = "postgres-sg"
  network_id = yandex_vpc_network.app.id

  ingress {
    protocol       = "TCP"
    port           = 6432
    v4_cidr_blocks = ["10.0.1.0/24"]  # only app subnet
  }
}

resource "yandex_mdb_postgresql_cluster" "example" {
  name               = "prod-postgres"
  environment        = "PRODUCTION"
  network_id         = yandex_vpc_network.app.id
  security_group_ids = [yandex_vpc_security_group.db_sg.id]  # added -- PASSES CKV_YC_1

  config {
    version = "15"
    resources {
      resource_preset_id = "s2.micro"
      disk_type_id        = "network-ssd"
      disk_size            = 20
    }
  }

  host {
    zone      = "ru-central1-a"
    subnet_id = yandex_vpc_subnet.app.id
  }
}
```

## Remediation steps
1. Create a `yandex_vpc_security_group` resource that allows only the necessary ingress traffic (e.g., the database port from application subnets, and any required management/monitoring access).
2. Reference that security group's ID (or IDs) in the cluster resource's `security_group_ids` attribute.
3. Avoid overly broad CIDR ranges (e.g., `0.0.0.0/0`) in the security group's ingress rules — scope to known subnets.
4. Adding a security group to an existing cluster is generally a non-disruptive, in-place update, but validate connectivity from all legitimate clients (app servers, admin tooling) before enforcing it in production.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/MDBSecurityGroup.py)
- [Yandex Cloud VPC security groups documentation](https://yandex.cloud/en/docs/vpc/concepts/security-groups)
