# CKV_AWS_226: Ensure DB instance gets all minor upgrades automatically
## Severity
**LOW** (score: 2.0/10)

Without automatic minor version upgrades, an RDS/Aurora instance can miss timely engine security patches, gradually increasing exposure to known database vulnerabilities.

## Summary
This check ensures that RDS database instances and cluster instances (`aws_db_instance`, `aws_rds_cluster_instance`) have `auto_minor_version_upgrade` enabled so they automatically receive minor engine version patches.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_db_instance`, `aws_rds_cluster_instance`

## Why it matters
RDS database engines (MySQL, PostgreSQL, MariaDB, SQL Server, Oracle, and Aurora-compatible engines) receive minor version releases that frequently include security patches for the underlying engine, not just bug fixes or feature additions. If `auto_minor_version_upgrade` is disabled, the database will remain on its currently deployed minor version indefinitely — there is no automated mechanism prompting an upgrade, so a known, publicly disclosed vulnerability in the database engine itself can persist unpatched for an extended period. Because RDS instances typically hold an organization's most sensitive structured data and are usually reachable by many application components, an unpatched engine-level vulnerability (e.g. a privilege escalation or remote code execution bug in the database software) represents a significant, often high-severity, risk if left unaddressed simply because no one manually triggered the minor-version upgrade.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `auto_minor_version_upgrade` attribute on either `aws_db_instance` or `aws_rds_cluster_instance`:
- If `auto_minor_version_upgrade` is set to `true`, the check **PASSES**.
- If it is `false` or absent, the check **FAILS** (default missing-block behavior, expected value defaults to `True`).

## Non-compliant example
```hcl
resource "aws_db_instance" "example" {
  identifier                  = "example-db"
  engine                      = "postgres"
  engine_version               = "15.4"
  instance_class              = "db.t3.medium"
  allocated_storage           = 20
  username                    = "admin"
  password                    = "changeme123!"
  auto_minor_version_upgrade  = false
  skip_final_snapshot         = true
}
```

## Remediated example
```hcl
resource "aws_db_instance" "example" {
  identifier                  = "example-db"
  engine                      = "postgres"
  engine_version               = "15.4"
  instance_class              = "db.t3.medium"
  allocated_storage           = 20
  username                    = "admin"
  password                    = "changeme123!"
  auto_minor_version_upgrade  = true
  skip_final_snapshot         = true
}
```

## Remediation steps
1. Set `auto_minor_version_upgrade = true` on the `aws_db_instance` (or `aws_rds_cluster_instance`) resource.
2. Configure an appropriate `maintenance_window` for the instance so automatic minor upgrades occur during a low-traffic period, since they can trigger a brief failover/restart.
3. For Multi-AZ deployments, minor version upgrades are typically applied to the standby first and then failed over, minimizing downtime — verify Multi-AZ is enabled for production workloads to reduce upgrade-related interruption risk.
4. If strict change control requires manual review of every engine patch before it's applied, document a compensating manual patching process and add a Checkov suppression comment explaining the exception, rather than silently leaving auto-upgrade disabled.
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DBInstanceMinorUpgrade.py)
- [AWS RDS: Working with automatic minor version upgrades](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html)
