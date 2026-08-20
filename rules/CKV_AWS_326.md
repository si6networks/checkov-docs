# CKV_AWS_326: Ensure that RDS Aurora Clusters have backtracking enabled
## Severity
**MEDIUM** (score: 5.0/10)

Backtracking is a recovery/availability feature for Aurora clusters, so its absence increases recovery time after accidental or malicious data changes rather than creating a direct confidentiality or access-control exposure.

## Summary
This check requires Aurora / Aurora-MySQL RDS clusters to set a non-zero `backtrack_window`, enabling Aurora's backtracking feature so the cluster can be rewound to an earlier point in time without a full restore.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_rds_cluster`
- **Engine scope:** Only `aurora` and `aurora-mysql` (backtracking is not available for Aurora PostgreSQL or plain MySQL/other engines)

## Why it matters
Backtracking lets you "rewind" an Aurora MySQL cluster to a specific point in time (within the backtrack window) in seconds, without provisioning a new cluster or restoring from a snapshot. Without it, recovering from an accidental `DROP TABLE`, a bad migration, ransomware-style data corruption, or an application bug that mass-deletes/corrupts rows requires a full point-in-time restore to a new cluster — which is slower, more disruptive, and costs more during an incident when time matters most. Enabling backtracking materially shortens recovery time objectives (RTO) for a class of operational and security incidents (e.g., a compromised application credential used to corrupt data).

## How Checkov evaluates this
The check (`RDSClusterAuroraBacktrack.py`) extends `BaseResourceNegativeValueCheck`:
1. If `engine` is set and not in `{"aurora", "aurora-mysql"}`, the result is `UNKNOWN` (backtracking doesn't apply).
2. It inspects the `backtrack_window` attribute. `0` (the Terraform default, meaning backtracking disabled) is a **forbidden value** → **FAILS**.
3. If the attribute is missing entirely, `missing_attribute_result=CheckResult.FAILED` also causes a **FAIL**.
4. Any non-zero value for `backtrack_window` → **PASSES**.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "bad_example" {
  cluster_identifier = "aurora-cluster"
  engine              = "aurora-mysql"
  engine_version      = "8.0.mysql_aurora.3.04.0"
  master_username     = "admin"
  master_password     = var.db_password
  # backtrack_window not set (defaults to 0 = disabled)
}
```

## Remediated example
```hcl
resource "aws_rds_cluster" "good_example" {
  cluster_identifier = "aurora-cluster"
  engine              = "aurora-mysql"
  engine_version      = "8.0.mysql_aurora.3.04.0"
  master_username     = "admin"
  master_password     = var.db_password

  # Enable backtracking, allowing rewind up to 24 hours
  backtrack_window = 86400
}
```

## Remediation steps
1. Set `backtrack_window` to a non-zero value (in seconds; up to 259200 seconds / 72 hours max for Aurora MySQL).
2. Size the window to your recovery objectives, balancing storage cost (backtracking retains extra change records) against RTO needs.
3. Confirm the cluster engine is `aurora` or `aurora-mysql` — this feature is unavailable on Aurora PostgreSQL; if you're on Postgres, rely on point-in-time restore instead and this check will correctly report `UNKNOWN`/not applicable.
4. This is a mutable, non-disruptive setting change via `aws_rds_cluster` — no replacement required, though enabling it does slightly increase storage I/O and cost.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterAuroraBacktrack.py)
- [AWS: Backtracking an Aurora DB cluster](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Managing.Backtrack.html)
