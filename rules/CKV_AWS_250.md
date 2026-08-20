# CKV_AWS_250: Ensure that RDS PostgreSQL instances use a non vulnerable version with the log_fdw extension

## Severity
**MEDIUM** (score: 5.0/10)

The check flags RDS/Aurora PostgreSQL engine versions carrying a disclosed, AWS-confirmed privilege-escalation vulnerability in the log_fdw extension, letting a low-privileged authenticated database user escalate beyond their granted role.

## Summary
This check ensures RDS PostgreSQL and Aurora PostgreSQL instances run an engine version that is not affected by the `log_fdw` extension privilege-escalation vulnerability described in AWS Security Bulletin [AWS-2022-004](https://aws.amazon.com/security/security-bulletins/AWS-2022-004/).

## Applicability
- **Framework:** Terraform
- **Resource types:** `aws_db_instance`, `aws_rds_cluster`

## Why it matters
AWS-2022-004 documented a vulnerability in the RDS-specific `log_fdw` foreign-data-wrapper extension for PostgreSQL, which could be leveraged by a database user to escalate privileges beyond what their granted role should allow, potentially reading or manipulating data or state that should be inaccessible to them. This is a real, disclosed CVE-class issue specific to the RDS/Aurora PostgreSQL platform (not the open-source extension), meaning any instance on the affected version ranges is running with a known privilege-escalation flaw available to any user who can execute SQL against the database. Since RDS handles the patching automatically once you're on a fixed engine version, the only action required is to stay on/above the patched minor version — an environment pinned to an old `engine_version` in Terraform will not get the fix even if AWS has released it, because RDS won't auto-upgrade minor versions unless `auto_minor_version_upgrade` is enabled or you explicitly bump the version.

## How Checkov evaluates this
The check reads the `engine` and `engine_version` attributes and applies version-specific thresholds:

**For `engine = "postgres"`** (parses `major.minor[.bugfix]`):
- PASS if major version ≥ 14
- PASS if major == 13 and minor > 2
- PASS if major == 12 and minor > 6
- PASS if major == 11 and minor > 11
- PASS if major == 10 and minor > 16
- PASS if major == 9, minor == 6, and bugfix > 21 (9.6.x uses `major.major.minor` numbering)
- Otherwise: FAIL

**For `engine = "aurora-postgresql"`** (parses `major.minor` only):
- PASS if major ≥ 12
- PASS if major == 11 and minor > 8
- PASS if major == 10 and minor > 13
- Otherwise: FAIL

If `engine_version` can't be parsed into the expected number of segments, or the engine is something else entirely, the result is `UNKNOWN` rather than PASS/FAIL.

## Non-compliant example
```hcl
resource "aws_db_instance" "postgres" {
  identifier     = "example-db"
  engine         = "postgres"
  engine_version = "12.5"          # vulnerable: 12.x <= 12.6
  instance_class = "db.t3.medium"
  allocated_storage = 20
}
```

## Remediated example
```hcl
resource "aws_db_instance" "postgres" {
  identifier     = "example-db"
  engine         = "postgres"
  engine_version = "12.7"          # <-- patched: 12.x > 12.6
  instance_class = "db.t3.medium"
  allocated_storage = 20
  auto_minor_version_upgrade = true
}
```

## Remediation steps
1. Identify the current `engine_version` of each `aws_db_instance`/`aws_rds_cluster` PostgreSQL or Aurora PostgreSQL resource.
2. Bump `engine_version` to a value at or above the patched threshold for your major version (see the "How Checkov evaluates this" section, or check the AWS bulletin for the authoritative list).
3. Set `auto_minor_version_upgrade = true` going forward so future security patches apply automatically during your maintenance window without manual Terraform changes.
4. Test the upgrade in a non-production environment first — even minor PostgreSQL version bumps can occasionally affect extension compatibility or query planner behavior.
5. Apply during a maintenance window; RDS minor version upgrades typically require a brief instance reboot/failover (Multi-AZ deployments minimize downtime via failover to the standby).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSPostgreSQLLogFDWExtension.py)
- [AWS Security Bulletin AWS-2022-004](https://aws.amazon.com/security/security-bulletins/AWS-2022-004/)
