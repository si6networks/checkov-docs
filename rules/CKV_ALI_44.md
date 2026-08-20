# CKV_ALI_44: Ensure MongoDB has Transparent Data Encryption Enabled
## Severity
**LOW** (score: 2.0/10)

Disabling Transparent Data Encryption leaves MongoDB data at rest unencrypted, so a stolen disk, snapshot, or backup directly exposes sensitive stored data.

## Summary
This check ensures that an Alibaba Cloud ApsaraDB for MongoDB instance has Transparent Data Encryption (TDE) enabled (`tde_status = "enabled"`) to encrypt data at rest.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_mongodb_instance`

## Why it matters
Transparent Data Encryption encrypts the underlying storage of database files, backups, and snapshots so that data at rest cannot be read if the physical storage medium, a snapshot, or a backup file is accessed outside the normal database access path — for example, if storage volumes are improperly decommissioned, a snapshot is inadvertently shared, or an attacker gains filesystem-level access to the host without going through the database's own authentication layer. Without TDE, a single misconfigured backup export or leaked snapshot can expose the entire dataset in cleartext, independent of any application-level security controls. Encryption at rest for databases holding regulated or sensitive data is a common requirement across compliance frameworks (GDPR, HIPAA, PCI-DSS) and a standard cloud security baseline.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `tde_status` attribute of `alicloud_mongodb_instance`.
- **FAIL** if `tde_status` is missing or set to any value other than `"enabled"` (e.g., `"disabled"`, the default).
- **PASS** if `tde_status = "enabled"`.

## Non-compliant example
```hcl
resource "alicloud_mongodb_instance" "example" {
  engine_version      = "4.4"
  db_instance_class   = "mdb.shard.2x.large"
  db_instance_storage = 20
  network_type        = "VPC"
  vswitch_id          = alicloud_vswitch.example.id
  # tde_status not set -> data at rest is not encrypted
}
```

## Remediated example
```hcl
resource "alicloud_mongodb_instance" "example" {
  engine_version      = "4.4"
  db_instance_class   = "mdb.shard.2x.large"
  db_instance_storage = 20
  network_type        = "VPC"
  vswitch_id          = alicloud_vswitch.example.id
  tde_status           = "enabled"  # <-- added: enables Transparent Data Encryption
}
```

## Remediation steps
1. Set `tde_status = "enabled"` on the `alicloud_mongodb_instance` resource.
2. Confirm the selected instance class/engine version supports TDE (Alibaba Cloud restricts TDE to certain MongoDB versions/specs — check the current product documentation before applying).
3. Be aware TDE typically cannot be disabled once enabled, and enabling it on an existing (already-created) instance may not be supported via simple attribute update — it may require creating a new instance with TDE enabled from the start and migrating data.
4. Combine with `ssl_action = "Open"` (CKV_ALI_42) for encryption in transit as well as at rest.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/MongoDBTransparentDataEncryptionEnabled.py)
