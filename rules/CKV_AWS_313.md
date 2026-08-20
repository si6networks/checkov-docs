# CKV_AWS_313: Ensure RDS cluster configured to copy tags to snapshots

## Severity
**LOW** (score: 2.0/10)

Failing to copy tags to RDS cluster snapshots is a metadata/hygiene gap that aids cost allocation and resource tracking but does not itself expose data or weaken access controls.

## Summary
This check ensures Amazon RDS (Aurora) clusters are configured to automatically propagate resource tags to any snapshots taken of the cluster.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_rds_cluster`

## Why it matters
Tags are frequently the operational and governance backbone for cloud environments — they drive cost allocation, environment identification (prod/staging/dev), data classification labels, backup/retention policy automation, and access-control conditions in IAM policies (e.g., `aws:ResourceTag`). When `copy_tags_to_snapshot` is left disabled, manual and automated snapshots of the cluster lose their tags, meaning: cost reports misattribute snapshot storage spend, tag-based IAM conditions or SCPs that restrict who can restore/delete snapshots silently stop applying, and automated lifecycle/cleanup tooling that keys off tags can no longer identify or protect sensitive snapshots — increasing the risk that a snapshot containing production data is deleted, over-shared, or left unmanaged. This maps to configuration/change-management baseline controls (NIST 800-53 CM-2).

## How Checkov evaluates this
A `BaseResourceValueCheck` that inspects the `copy_tags_to_snapshot` attribute on `aws_rds_cluster`:
- **PASS** if `copy_tags_to_snapshot` is set to `true`.
- **FAIL** if it is absent, `false`, or any other falsy value (Terraform's default for this attribute is `false`).

## Non-compliant example
```hcl
resource "aws_rds_cluster" "example" {
  cluster_identifier      = "example-aurora-cluster"
  engine                  = "aurora-postgresql"
  engine_version          = "15.4"
  master_username         = "admin"
  master_password         = var.db_password
  # copy_tags_to_snapshot not set -> defaults to false
  tags = {
    Environment = "production"
    DataClass   = "confidential"
  }
}
```

## Remediated example
```hcl
resource "aws_rds_cluster" "example" {
  cluster_identifier      = "example-aurora-cluster"
  engine                  = "aurora-postgresql"
  engine_version          = "15.4"
  master_username         = "admin"
  master_password         = var.db_password
  copy_tags_to_snapshot   = true          # snapshots inherit cluster tags
  tags = {
    Environment = "production"
    DataClass   = "confidential"
  }
}
```

## Remediation steps
1. Add `copy_tags_to_snapshot = true` to the `aws_rds_cluster` resource.
2. This is an in-place attribute update — no cluster replacement or downtime is required (Terraform will issue a modify-db-cluster call).
3. Confirm existing tags on the cluster are accurate and complete, since they will now propagate forward to every future automated and manual snapshot.
4. Note this setting only affects snapshots taken *after* the change; existing snapshots are not retroactively tagged.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterCopyTags.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Managing.Backups.html
