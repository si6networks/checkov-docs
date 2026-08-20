# CKV2_AWS_60: Ensure RDS instance with copy tags to snapshots is enabled

## Severity
**LOW** (score: 2.0/10)

Copy-tags-to-snapshot only affects metadata propagation and cost/asset-tracking hygiene on RDS snapshots, with no bearing on confidentiality, integrity, or availability of the data itself.

## Summary
This check requires non-Aurora/Neptune/DocumentDB `aws_db_instance` resources to explicitly set `copy_tags_to_snapshot = true`, so that resource tags applied to the instance are automatically propagated to its snapshots.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_db_instance` (specifically excluded when `engine` is `neptune`, `aurora`, or `docdb`, which manage tagging differently or via cluster-level resources)

## Why it matters
Tags are frequently the backbone of governance: cost allocation, environment/owner attribution, automated backup/retention policies, and access-control conditions (IAM policies using `aws:ResourceTag`) often key off resource tags. If snapshots don't inherit the instance's tags, snapshots can become "orphaned" from a governance perspective — untagged copies of production data that don't show up in cost reports, aren't caught by tag-based retention/cleanup automation, and may not be covered by tag-based IAM restrictions, increasing the risk that sensitive snapshot data lingers untracked or is exposed to broader access than intended (e.g., a `PublicSnapshot` sharing policy scoped by tag). It's primarily a governance/compliance and cost-hygiene control rather than a direct exploit path, but untracked snapshots are a recurring source of both compliance findings and accidental data exposure.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) with three `and`-ed conditions on `aws_db_instance`:
1. `copy_tags_to_snapshot` **equals** `"true"`.
2. `copy_tags_to_snapshot` **exists** (i.e., must be explicitly set, not merely defaulted).
3. `engine` is **not within** `["neptune", "aurora", "docdb"]` — these engines are excluded from the check entirely (they use cluster-level or different tagging mechanisms).

For applicable engines (e.g., `mysql`, `postgres`, `mariadb`, `oracle-*`, `sqlserver-*`), the attribute must be explicitly present and set to `true`; otherwise the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier     = "app-prod-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r6g.large"
  allocated_storage = 100
  # copy_tags_to_snapshot not set -> FAILS
  tags = {
    Environment = "production"
    Owner       = "platform-team"
  }
}
```

## Remediated example
```hcl
resource "aws_db_instance" "app_db" {
  identifier             = "app-prod-db"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.r6g.large"
  allocated_storage      = 100
  copy_tags_to_snapshot  = true   # added
  tags = {
    Environment = "production"
    Owner       = "platform-team"
  }
}
```

## Remediation steps
1. Add `copy_tags_to_snapshot = true` explicitly to every non-Aurora/Neptune/DocumentDB `aws_db_instance`.
2. This is a metadata-only setting — it takes effect immediately on apply without downtime or instance replacement.
3. For Aurora clusters, use the equivalent setting on `aws_rds_cluster` (`copy_tags_to_snapshot`) instead, since this specific check does not cover cluster resources.
4. Verify existing manual/automated snapshots taken before this change won't retroactively gain tags — only snapshots created after enabling this setting inherit tags.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/RDSEnableCopyTagsToSnapshot.json
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html
