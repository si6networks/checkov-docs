# CKV_TC_10: Ensure Tencent Cloud MySQL instances intranet ports are not set to the default 3306

## Severity
**LOW** (score: 3.0/10)

Changing the database port off the default is a defense-in-depth obscurity measure that raises the bar for automated lateral-movement tooling but does not by itself close any real access-control gap, since security groups and authentication remain the actual controlling defenses.

## Summary
This check ensures that Tencent Cloud MySQL (CDB) instances do not use the well-known default MySQL intranet port 3306.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource type `tencentcloud_mysql_instance` (Tencent Cloud provider).

## Why it matters
Leaving a database on its well-known default port makes it a predictable, easy target for automated internal reconnaissance: any attacker or malicious insider who gains a foothold anywhere on the VPC/intranet can immediately assume the database is listening on 3306 and target it directly, without needing to first discover the port through scanning. While changing the port is not a substitute for real access controls (security groups, authentication, TLS), it is a cheap additional layer of obscurity that increases the effort required for lateral movement and automated exploitation tooling that hardcodes the default MySQL port, and it is a standard defense-in-depth control expected in hardened database deployments.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the `intranet_port` attribute of a `tencentcloud_mysql_instance`. `3306` is the forbidden value: if `intranet_port` is explicitly set to `3306` (or left at its default, which is `3306`), the check **FAILS**. If `intranet_port` is set to any other value, the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_mysql_instance" "example" {
  instance_name = "app-db"
  mem_size      = 4000
  volume_size   = 100
  vpc_id        = tencentcloud_vpc.app_vpc.id
  subnet_id     = tencentcloud_subnet.app_subnet.id
  intranet_port = 3306
}
```

## Remediated example
```hcl
resource "tencentcloud_mysql_instance" "example" {
  instance_name = "app-db"
  mem_size      = 4000
  volume_size   = 100
  vpc_id        = tencentcloud_vpc.app_vpc.id
  subnet_id     = tencentcloud_subnet.app_subnet.id
  intranet_port = 33061   # non-default port
}
```

## Remediation steps
1. Set `intranet_port` on `tencentcloud_mysql_instance` to a non-default value (any port other than 3306, chosen from your organization's approved port range).
2. Update all application connection strings / configuration referencing the database to use the new port.
3. Coordinate this change with a maintenance window if the instance is already in production, since existing client connections and connection pools will need to reconnect on the new port.
4. Treat this as a defense-in-depth measure only — continue to enforce security groups scoping database access to specific application subnets and strong authentication regardless of the port used.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CDBIntranetPort.py
