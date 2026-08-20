# CKV_AWS_16: Ensure all data stored in the RDS is securely encrypted at rest
## Severity
**LOW** (score: 2.0/10)

RDS instances commonly hold core application and customer data, and disabling storage encryption means that data is stored in the clear on underlying disks and in any snapshots taken from the instance, exposing it if storage media or snapshots are ever accessed outside the intended boundary.

## Summary
This check verifies that a non-Aurora RDS instance has storage encryption (`storage_encrypted`) enabled at rest.

## Applicability
Terraform (`aws_db_instance`) and CloudFormation (`AWS::RDS::DBInstance`). Aurora engines are exempted from this specific check (see below), since Aurora encryption is configured on the cluster resource rather than the instance.

## Why it matters
An RDS instance's underlying storage (data files, transaction logs, automated backups, read replicas, and snapshots derived from it) holds the full contents of the database — very often the most sensitive data in an application (customer PII, payment data, credentials, health records). Without `storage_encrypted`, that data sits in plaintext on the underlying EBS-backed storage. This matters concretely because: unencrypted storage means any unauthorized access to the underlying volume, an improperly shared/copied snapshot, or a misconfigured cross-account restore exposes the raw data with no cryptographic barrier; encryption cannot be enabled after creation (it is fixed at instance-creation time), so failing to set it now means an eventual costly migration; and virtually every compliance framework (PCI-DSS, HIPAA, SOC 2, ISO 27001) explicitly requires encryption at rest for regulated data stores like databases.

## How Checkov evaluates this
Both language checks first inspect the `Engine`: if it contains `"aurora"`, the check returns `UNKNOWN` (not applicable to this resource — Aurora storage encryption is configured on the `aws_rds_cluster`/`AWS::RDS::DBCluster`, not the instance). Otherwise the check falls to `BaseResourceValueCheck` on `StorageEncrypted` (CloudFormation `Properties.StorageEncrypted`) / `storage_encrypted` (Terraform): `PASSED` if `true`, `FAILED` if `false` or unset (defaults to `false`).

## Non-compliant example
```hcl
resource "aws_db_instance" "customers" {
  identifier        = "customers-db"
  engine            = "mysql"
  engine_version     = "8.0"
  instance_class     = "db.r6g.large"
  allocated_storage  = 100
  username           = "app"
  password           = var.db_password
  # storage_encrypted not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_db_instance" "customers" {
  identifier        = "customers-db"
  engine            = "mysql"
  engine_version     = "8.0"
  instance_class     = "db.r6g.large"
  allocated_storage  = 100
  username           = "app"
  password           = var.db_password
  storage_encrypted  = true # <-- added
  kms_key_id         = aws_kms_key.rds.arn
}
```

## Remediation steps
1. Set `storage_encrypted = true` (Terraform) or `StorageEncrypted: true` (CloudFormation) on the `aws_db_instance`/`AWS::RDS::DBInstance` resource.
2. Optionally set `kms_key_id` to a customer-managed CMK; if omitted, AWS uses the default `aws/rds` managed key.
3. **Critical caveat**: storage encryption cannot be enabled on an existing, running unencrypted instance. To remediate an already-provisioned unencrypted instance you must: take a snapshot, copy the snapshot with encryption enabled (specifying a KMS key), and restore a new instance from the encrypted snapshot copy — then cut over application connections and decommission the old instance. Plan for a maintenance window and connection-string changes.
4. For Aurora, this check does not apply (`UNKNOWN`) — instead ensure `storage_encrypted` is set on the corresponding `aws_rds_cluster`.
5. Verify read replicas inherit encryption correctly; a replica of an encrypted source is encrypted, but cross-region encrypted replicas require an explicit KMS key in the destination region.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RDSEncryption.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
