# CKV2_AWS_58: Ensure AWS Neptune cluster deletion protection is enabled

## Severity
**LOW** (score: 2.0/10)

Missing deletion protection on a Neptune cluster is primarily an availability/data-loss risk (accidental or malicious deletion of a graph database), not a confidentiality or access-control gap, so it lands in the availability-impact medium band.

## Summary
This check requires that every `aws_neptune_cluster` resource explicitly sets `deletion_protection = true`, preventing the cluster from being deleted without first disabling that protection.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_neptune_cluster`

## Why it matters
Neptune is typically used for graph data (fraud detection graphs, knowledge graphs, recommendation engines, identity/relationship graphs) that can be costly or impossible to fully reconstruct. Without deletion protection, a single mistaken `terraform destroy`, a misapplied Terraform plan targeting the wrong workspace/state, a compromised CI/CD pipeline, or an over-privileged operator running an ad hoc `aws neptune delete-db-cluster` can permanently destroy the cluster and its data (absent a very recent, complete snapshot). Deletion protection is a low-cost, no-downside guardrail against irreversible, accidental data loss — it does not affect performance, cost, or availability, and can be temporarily disabled and re-enabled for planned decommissioning.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy). Its definition is a single `attribute` condition:
- **Resource type:** `aws_neptune_cluster`
- **Attribute:** `deletion_protection`
- **Operator:** `equals_ignore_case`
- **Required value:** `"true"`

If `deletion_protection` is absent, `false`, or any value other than `true` (case-insensitively), the check **FAILS**. Only an explicit `deletion_protection = true` **PASSES**.

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier                  = "fraud-graph-prod"
  engine                              = "neptune"
  backup_retention_period             = 7
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = false
  # deletion_protection not set -> defaults to false -> FAILS
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier                  = "fraud-graph-prod"
  engine                              = "neptune"
  backup_retention_period             = 7
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = false
  deletion_protection                 = true  # added
}
```

## Remediation steps
1. Add `deletion_protection = true` to every `aws_neptune_cluster` resource.
2. If the cluster already exists without protection, applying this change is a non-destructive in-place update (no replacement, no downtime).
3. For legitimate teardown (e.g., decommissioning an environment), explicitly set `deletion_protection = false` in a preceding, reviewed change before running `terraform destroy` — do not disable protection as a routine matter.
4. Combine with `skip_final_snapshot = false` (or an explicit `final_snapshot_identifier`) so that even an authorized deletion leaves a recoverable snapshot.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/NeptuneDeletionProtectionEnabled.json
- AWS docs: https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-deletion-protection.html
