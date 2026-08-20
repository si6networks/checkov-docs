# CKV_AWS_343: Ensure Amazon Redshift clusters should have automatic snapshots enabled
## Severity
**HIGH** (score: 7.5/10)

Disabling automated snapshots on a Redshift cluster removes the ability to recover the data warehouse after accidental deletion, corruption, or a ransomware-style event, an availability/recovery gap rather than a direct exposure.

## Summary
Ensures Amazon Redshift clusters keep automated backups turned on by requiring a non-zero `automated_snapshot_retention_period`.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource type**: `aws_redshift_cluster`

## Why it matters
Redshift automated snapshots are the primary backup and disaster-recovery mechanism for a data warehouse cluster — they capture incremental snapshots and allow point-in-time restore. Setting `automated_snapshot_retention_period` to `0` disables automatic snapshots entirely. If that happens and the cluster later suffers data corruption, an accidental `DROP`/`TRUNCATE`, a failed schema migration, node hardware failure, or a ransomware-style destructive event, there is no automated recovery point to restore from — only whatever manual snapshots (if any) happen to exist. This directly threatens data durability and business continuity, and undermines compliance controls (e.g. NIST 800-53 CP-9/CP-10 contingency planning) that require regular, automatic backups of production data stores.

## How Checkov evaluates this
This is a Terraform "negative value" check that inspects the `automated_snapshot_retention_period` attribute:
- **FAIL**: the value is exactly `0` (the forbidden value) — this explicitly disables automated snapshots.
- **PASS**: the value is set to any non-zero number (1–35 days, per the AWS Redshift API).
- **PASS (missing attribute)**: if `automated_snapshot_retention_period` is omitted entirely, the check passes (`missing_attribute_result=CheckResult.PASSED`), because the AWS default retention period is 1 day (not 0).

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier                 = "analytics-cluster"
  database_name                      = "analytics"
  master_username                    = "admin"
  master_password                    = var.redshift_password
  node_type                          = "dc2.large"
  cluster_type                       = "single-node"
  automated_snapshot_retention_period = 0   # disables automated backups
}
```

## Remediated example
```hcl
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier                 = "analytics-cluster"
  database_name                      = "analytics"
  master_username                    = "admin"
  master_password                    = var.redshift_password
  node_type                          = "dc2.large"
  cluster_type                       = "single-node"
  automated_snapshot_retention_period = 7   # retain automated snapshots for 7 days
}
```

## Remediation steps
1. Find every `aws_redshift_cluster` resource in your Terraform configuration.
2. Set `automated_snapshot_retention_period` to a value between 1 and 35 based on your recovery point objective (RPO) and compliance requirements (commonly 7 or 30 days).
3. If the attribute is currently omitted, no change is strictly required for this check to pass, but explicitly setting a retention period is best practice for clarity and auditability.
4. Consider also configuring cross-region snapshot copy (`aws_redshift_snapshot_copy` / `snapshot_copy` block) for disaster recovery across regions.
5. Applying this change does not require cluster replacement — it is an in-place modification.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterAutoSnap.py
- AWS docs: https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html
