# CKV2_AWS_59: Ensure ElasticSearch/OpenSearch has dedicated master node enabled

## Severity
**LOW** (score: 2.0/10)

Lacking a dedicated master node is an operational-resilience best practice for cluster stability under load, not a control that closes an actual attack path, so it carries minimal direct exploitability.

## Summary
This check requires that `aws_elasticsearch_domain` and `aws_opensearch_domain` resources set `cluster_config.dedicated_master_enabled = true`, so cluster management tasks run on nodes separate from the data/query nodes.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_opensearch_domain`, `aws_elasticsearch_domain`

## Why it matters
Without dedicated master nodes, the cluster's master-eligible role is served by the same nodes handling indexing and search traffic. Under heavy query or indexing load, this can starve master duties (cluster state updates, shard allocation, node discovery), leading to master node instability, split-brain-like behavior, delayed shard reassignment, or full cluster unavailability during traffic spikes — precisely the moment reliability matters most. Dedicated master nodes isolate cluster coordination from data-plane load, materially improving availability and resilience for anything beyond small/dev clusters, and are an AWS-recommended best practice for production OpenSearch/Elasticsearch domains.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy). Its single `attribute` condition:
- **Resource types:** `aws_opensearch_domain`, `aws_elasticsearch_domain`
- **Attribute:** `cluster_config.dedicated_master_enabled`
- **Operator:** `equals`
- **Required value:** `"true"`

If `dedicated_master_enabled` is missing, `false`, or not set to `true` inside the `cluster_config` block, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_opensearch_domain" "logs" {
  domain_name    = "app-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "r6g.large.search"
    instance_count = 3
    # dedicated_master_enabled not set -> FAILS
  }
}
```

## Remediated example
```hcl
resource "aws_opensearch_domain" "logs" {
  domain_name    = "app-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type            = "r6g.large.search"
    instance_count           = 3
    dedicated_master_enabled = true          # added
    dedicated_master_type    = "r6g.large.search"
    dedicated_master_count   = 3
  }
}
```

## Remediation steps
1. Add `dedicated_master_enabled = true` inside the `cluster_config` block.
2. Also set `dedicated_master_type` (often a smaller/cheaper instance type is sufficient since master nodes don't serve query traffic) and `dedicated_master_count` (AWS requires 3 or 5 for quorum/odd-numbered fault tolerance).
3. Note: enabling dedicated master nodes on an existing domain triggers a blue/green deployment by AWS (no data loss, but a maintenance window with potential brief latency impact) — plan for a change window in production.
4. Budget for the additional dedicated master instances, which incur their own hourly cost even though they don't serve application traffic.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/ElasticSearchDedicatedMasterEnabled.json
- AWS docs: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-dedicatedmasternodes.html
