# CKV_ALI_22: Ensure Transparent Data Encryption is Enabled on instance
## Severity
**LOW** (score: 2.0/10)

Without Transparent Data Encryption, data stored at rest in the RDS instance (including backups) is unencrypted, so a compromised disk, snapshot, or storage backend directly exposes sensitive database contents.

## Summary
This check verifies that Transparent Data Encryption (TDE) is enabled on Alibaba Cloud RDS instances running supported MySQL or SQL Server engine versions.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_db_instance`
- Only evaluated (PASS/FAIL) when `engine` is `"MySQL"` or `"SQLServer"` **and** `engine_version` is one of the versions that support TDE (MySQL: `5.6`, `5.7`, `8`, `8.0`; SQL Server: `08r2_ent_ha`, `2012_ent_ha`, `2016_ent_ha`, `2017_ent`, `2019_std_ha`, `2019_ent`). Other engines/versions (e.g. PostgreSQL, or unsupported MySQL/SQL Server versions) return `UNKNOWN` — not evaluated.

## Why it matters
TDE encrypts database files at rest — data files, log files, and backups — so that if the underlying storage volume, a snapshot, or a backup file is accessed outside the database engine's normal access controls (e.g. through a leaked snapshot, an improperly disposed disk, or unauthorized storage-layer access), the data itself remains unreadable without the encryption key. This is a baseline data-at-rest protection control for any RDS instance holding sensitive data, and is frequently a compliance requirement (PCI-DSS, HIPAA) independent of network-layer or application-layer encryption.

## How Checkov evaluates this
Custom `scan_resource_conf` logic on `alicloud_db_instance`:
1. Only proceeds if `engine` is exactly `"MySQL"` or `"SQLServer"`.
2. Within that, only proceeds if `engine_version` is present and matches one of the supported TDE version lists.
3. If both conditions hold, checks `tde_status`: PASS if `tde_status == "Enabled"`, otherwise FAIL.
4. If the engine/version combination doesn't match the supported set, the result is `UNKNOWN` (not evaluated) rather than PASS or FAIL.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s1.small"
  instance_storage = "20"
  vswitch_id       = "vsw-example"
  tde_status       = "Disabled"   # <-- fails: TDE not enabled on a supported engine/version
}
```

## Remediated example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "MySQL"
  engine_version   = "8.0"
  instance_type    = "rds.mysql.s1.small"
  instance_storage = "20"
  vswitch_id       = "vsw-example"
  tde_status       = "Enabled"    # <-- fix: TDE enabled
}
```

## Remediation steps
1. Confirm the RDS instance's `engine`/`engine_version` supports TDE (MySQL 5.6/5.7/8/8.0, or the listed SQL Server enterprise-HA versions).
2. Set `tde_status = "Enabled"`.
3. Note: enabling TDE on an existing Alibaba Cloud RDS instance is typically a one-way operation that cannot be reversed, and depending on engine may require the instance to be in a supported state — test in a non-production instance first and review current Alibaba Cloud RDS documentation for engine-specific caveats.
4. If using an unsupported engine/version, consider upgrading to a supported version if encryption at rest is a hard requirement, or rely on encrypted underlying disks (`alicloud_disk` encryption) as an alternative at-rest control.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSTransparentDataEncryptionEnabled.py)
- [Alibaba Cloud RDS instance resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance)
- [ApsaraDB for RDS instance creation / engine reference](https://www.alibabacloud.com/help/en/apsaradb-for-rds/latest/create-an-instance)
