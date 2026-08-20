# CKV_AWS_388: Ensure AWS Aurora PostgreSQL is not exposed to local file read vulnerability

## Severity
**HIGH** (score: 7.5/10)

Running an Aurora PostgreSQL version known to be exposed to the local-file-read vulnerability lets an authenticated database user read arbitrary files on the underlying host, leaking secrets or configuration data.

## Summary
This check flags Aurora PostgreSQL `aws_db_instance` resources pinned to specific patched-but-still-vulnerable engine versions (10.11–10.13, 11.6–11.8) that are affected by a known local file read vulnerability.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_db_instance`

## Why it matters
This check targets a specific, named CVE-class vulnerability in certain Aurora PostgreSQL engine versions that allowed a database user with sufficient privileges to read arbitrary files from the underlying host's local filesystem (a "local file read" / LFI-style vulnerability) via crafted SQL operations (e.g., through certain extension or `COPY`/`lo_import`-style functionality bugs, or logical-replication/plugin bugs typical of this CVE class in that era of PostgreSQL). Running one of the affected versions means:

- A malicious or compromised low-privilege database user could potentially read sensitive host-level files (which, depending on the underlying architecture, could include secrets, configuration files, or credentials accessible to the DB engine process), materially expanding the blast radius of what should be an application-layer database compromise into a filesystem-level information disclosure.
- Since these are old, specific point versions, this is unambiguously a "you must patch" finding rather than a hardening suggestion — unlike many Checkov checks, there's no legitimate reason to intentionally stay on one of these versions.

## How Checkov evaluates this
The check inspects the `aws_db_instance` resource's `engine` and `engine_version` attributes:

- It only evaluates instances where `engine` contains `"aurora-postgresql"`.
- Within those, if `engine_version` exactly matches one of: `10.11`, `10.12`, `10.13`, `11.6`, `11.7`, `11.8` → the check **FAILS**.
- Any other engine version (older, or newer/patched) → the check **PASSES**.

Note this is a narrow, version-pinned check — it will not catch every vulnerable Aurora PostgreSQL version, only this specific enumerated list corresponding to the known CVE-affected releases.

## Non-compliant example
```hcl
resource "aws_db_instance" "example" {
  identifier     = "example-aurora-instance"
  engine         = "aurora-postgresql"
  engine_version = "11.7"
  instance_class = "db.r5.large"
}
```

## Remediated example
```hcl
resource "aws_db_instance" "example" {
  identifier     = "example-aurora-instance"
  engine         = "aurora-postgresql"
  engine_version = "15.4"
  instance_class = "db.r5.large"
}
```

## Remediation steps
1. Upgrade the Aurora PostgreSQL engine version away from any of `10.11`, `10.12`, `10.13`, `11.6`, `11.7`, `11.8` to the latest supported minor/major version in the same major line (or a newer major version if you're prepared for the associated compatibility testing).
2. Check AWS's Aurora PostgreSQL release notes for the specific CVE this addresses and confirm the target version is patched.
3. Test the upgrade in a non-production cluster first — a major version upgrade (e.g., 10.x/11.x → 15.x) requires application compatibility testing and may require addressing deprecated SQL syntax or extension changes.
4. Engine version upgrades on Aurora typically happen via in-place modification (`aws_rds_cluster`/`aws_db_instance` `engine_version` change) with a maintenance window, and can involve a brief failover; plan for a maintenance window rather than assuming zero downtime, especially for major version jumps.
5. Enable `auto_minor_version_upgrade = true` going forward so future minor-version security patches are applied automatically without requiring manual Terraform changes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/UnpatchedAuroraPostgresDB.py)
- [Amazon Aurora PostgreSQL database engine updates documentation](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Updates.html)
