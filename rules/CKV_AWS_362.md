# CKV_AWS_362: Neptune DB clusters should be configured to copy tags to snapshots

## Severity
**LOW** (score: 2.0/10)

Missing tag propagation to snapshots is a governance/hygiene gap that can weaken tag-based IAM policy enforcement and asset inventory accuracy, but it does not itself create a direct exploitable exposure.

## Summary
This check ensures that an `aws_neptune_cluster` resource has `copy_tags_to_snapshot` enabled, so that resource tags (used for ownership, cost allocation, and access-control policies) are propagated to any snapshots taken of the cluster.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Check type:** resource check
- **Entities:** `aws_neptune_cluster`

## Why it matters
Tags on AWS resources frequently drive more than cost allocation — they are commonly used in IAM policy conditions (`aws:ResourceTag`), automated compliance scanning, resource-ownership tracking, and backup lifecycle automation. If snapshots don't inherit the cluster's tags, several problems follow: tag-based IAM policies that are supposed to restrict who can access/restore a snapshot silently fail to apply (since the snapshot has no tags to match against), governance tooling that inventories resources by tag will miss untagged snapshots, and cost allocation reports will misattribute snapshot storage costs. In the worst case, an untagged snapshot containing sensitive graph data could evade tag-based data classification or retention/deletion policies, creating a lingering unmanaged copy of sensitive data.

## How Checkov evaluates this
Straightforward attribute check (`BaseResourceValueCheck`) that inspects the `copy_tags_to_snapshot` attribute on `aws_neptune_cluster`. If not set to `true`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier     = "example-neptune"
  engine                 = "neptune"
  copy_tags_to_snapshot  = false

  tags = {
    Environment = "production"
    Owner       = "data-platform"
  }
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster" "graph_db" {
  cluster_identifier     = "example-neptune"
  engine                 = "neptune"
  copy_tags_to_snapshot  = true

  tags = {
    Environment = "production"
    Owner       = "data-platform"
  }
}
```

## Remediation steps
1. Set `copy_tags_to_snapshot = true` on the `aws_neptune_cluster` resource.
2. This is a mutable attribute; applying does not require replacing the cluster.
3. Confirm that any tag-based IAM policies or automation that reference snapshot tags now function as expected against newly created snapshots (existing snapshots taken before the change will not retroactively gain tags).
4. Ensure your tagging standard (owner, environment, data-classification) is applied consistently at the cluster level so it propagates correctly.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneDBClustersCopyTagsToSnapshots.py
- AWS docs: https://docs.aws.amazon.com/neptune/latest/userguide/backup-restore-copy-tags-snapshot.html
