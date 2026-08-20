# CKV_AWS_139: Ensure that RDS clusters have deletion protection enabled

## Severity
**LOW** (score: 2.0/10)

Missing deletion protection on RDS clusters risks accidental or malicious destruction of a data store, an availability/integrity concern rather than a direct exposure of data.

## Summary
This check requires `aws_rds_cluster` resources to set `deletion_protection = true`, preventing the cluster from being deleted (accidentally or maliciously) without first explicitly disabling the protection flag.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_rds_cluster`

## Why it matters
Without deletion protection, an RDS cluster can be deleted with a single API call, CLI command, `terraform destroy`, or console click — whether by human error (wrong environment selected, a mistaken `terraform destroy` against production, a misconfigured CI/CD pipeline), a bug in automation, or a malicious actor who has obtained credentials/IAM permissions sufficient to call `DeleteDBCluster`. For a production database, deletion is one of the most severe possible incidents: total loss of the live dataset unless a very recent snapshot exists, plus extended downtime while any recovery occurs. Deletion protection acts as a mandatory "are you sure" guard that must be deliberately removed before deletion succeeds, closing off the most catastrophic single-action failure mode.

## How Checkov evaluates this
This is a plain attribute-value check (`BaseResourceValueCheck` with no `get_expected_value` override, so the default expected value of `True` is used):
- Inspects the `deletion_protection` attribute.
- **PASS** if `deletion_protection = true`.
- **FAIL** if set to `false` or left unset (AWS's default for `aws_rds_cluster` is `false`).

## Non-compliant example
```hcl
resource "aws_rds_cluster" "app" {
  cluster_identifier      = "app-cluster"
  engine                  = "aurora-postgresql"
  master_username         = "admin"
  master_password         = var.db_password
  # deletion_protection not set -> defaults to false -> FAIL
}
```

## Remediated example
```hcl
resource "aws_rds_cluster" "app" {
  cluster_identifier      = "app-cluster"
  engine                  = "aurora-postgresql"
  master_username         = "admin"
  master_password         = var.db_password
  deletion_protection     = true   # added
}
```

## Remediation steps
1. Add `deletion_protection = true` to every production (and ideally all) `aws_rds_cluster` resource.
2. Note that with deletion protection enabled, both the AWS console/API and `terraform destroy` will refuse to delete the cluster until protection is explicitly disabled first (`deletion_protection = false`, applied, then delete) — build this into any legitimate decommissioning runbook.
3. Also enable deletion protection on the corresponding `aws_rds_cluster_instance` resources' parent cluster and consider `skip_final_snapshot = false` so a final snapshot is always taken even in the rare case deletion is intentionally performed.
4. This is a non-disruptive metadata change with no downtime or replacement required.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSDeletionProtection.py)
- [AWS: Deletion protection for RDS DB instances and clusters](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html)
