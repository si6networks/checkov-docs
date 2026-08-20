# CKV_ALI_30: Ensure RDS instance auto upgrades for minor versions
## Severity
**LOW** (score: 2.0/10)

Disabling automatic minor-version upgrades delays the application of vendor security patches to the RDS engine, leaving known vulnerabilities unpatched for longer than necessary.

## Summary
This check verifies that Alibaba Cloud RDS instances are configured to automatically apply minor engine version upgrades.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_db_instance`

## Why it matters
Database engine minor version releases frequently include security patches for newly disclosed vulnerabilities (privilege escalation, authentication bypass, remote code execution, etc.) as well as important bug fixes. An RDS instance that never receives minor version upgrades will drift further behind on patches over time, remaining exposed to known, already-fixed vulnerabilities for as long as it stays on an outdated build. Automatic minor-version upgrades ensure the database engine stays current with vendor-issued security fixes without relying on manual, easily-forgotten maintenance processes.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `auto_upgrade_minor_version` attribute on `alicloud_db_instance`:
- Expected value is `"Auto"`.
- FAILS if `auto_upgrade_minor_version` is unset or set to anything else (e.g. `"Manual"`).
- PASSES if `auto_upgrade_minor_version = "Auto"`.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine                     = "MySQL"
  engine_version             = "8.0"
  instance_type              = "rds.mysql.s1.small"
  instance_storage            = "20"
  vswitch_id                  = "vsw-example"
  auto_upgrade_minor_version  = "Manual"   # <-- fails: minor version patches not applied automatically
}
```

## Remediated example
```hcl
resource "alicloud_db_instance" "example" {
  engine                     = "MySQL"
  engine_version             = "8.0"
  instance_type              = "rds.mysql.s1.small"
  instance_storage            = "20"
  vswitch_id                  = "vsw-example"
  auto_upgrade_minor_version  = "Auto"     # <-- fix: minor version upgrades applied automatically
}
```

## Remediation steps
1. Locate `alicloud_db_instance` resources with `auto_upgrade_minor_version` unset or set to `"Manual"`.
2. Set `auto_upgrade_minor_version = "Auto"`.
3. Understand the operational tradeoff: automatic minor upgrades are applied during the instance's maintenance window, which may involve a brief failover/restart for some engines/topologies — schedule the maintenance window during low-traffic periods and ensure your application handles transient connection drops gracefully (e.g. via connection retry logic).
4. For environments requiring strict change control (e.g. regulated production databases where every change must be tested first), consider `"Manual"` combined with a documented, enforced process to apply minor version patches promptly after they're released and validated in staging — and suppress this check with an inline justification comment if that's your organization's deliberate policy.
5. Re-apply and re-scan to confirm the setting took effect.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSInstanceAutoUpgrade.py)
- [Alibaba Cloud RDS instance resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance)
