# CKV_AWS_318: Ensure Elasticsearch domains are configured with at least three dedicated master nodes for HA

## Severity
**MEDIUM** (score: 5.0/10)

Fewer than three dedicated master nodes is a high-availability/resilience gap for the cluster's control plane, affecting uptime rather than confidentiality or access control.

## Summary
This check ensures Elasticsearch/OpenSearch domains use at least three dedicated master nodes combined with zone awareness, so the cluster maintains quorum and remains available across an Availability Zone failure.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (AWS provider)
- **Resource types:** `aws_elasticsearch_domain`, `aws_opensearch_domain`

## Why it matters
Elasticsearch/OpenSearch master nodes are responsible for cluster-wide state: index creation/deletion, shard allocation, and node membership. Master elections use a quorum-based algorithm, which requires an **odd** number of dedicated master nodes (AWS recommends and Checkov enforces a minimum of 3) to avoid split-brain scenarios where the cluster cannot agree on state after a network partition or node loss. Combined with `zone_awareness_enabled`, data and master nodes are spread across multiple Availability Zones, so the loss of an entire AZ (a real, non-hypothetical failure mode in AWS) does not take down cluster quorum or the whole domain. A domain without enough dedicated masters, or without zone awareness, is a single point of failure: an AZ outage or a master node crash can leave the domain unable to serve writes, update mappings, or in the worst case enter a split-brain state with divergent cluster views. This maps to contingency planning and resilience controls (NIST 800-53 CP-10, SC-5(2), SC-36).

## How Checkov evaluates this
Inspects the `cluster_config` block:
- Reads `dedicated_master_count` — **must be an integer >= 3**.
- If that condition holds, also checks `zone_awareness_enabled` is truthy.
- **PASS** only if both `dedicated_master_count >= 3` **and** `zone_awareness_enabled` is true.
- **FAIL** if `cluster_config` is missing, `dedicated_master_count` is absent/less than 3, or zone awareness is not enabled (note: dedicated master nodes must also be separately enabled via `dedicated_master_enabled = true` for `dedicated_master_count` to take effect in AWS, though the check itself only inspects the count and zone-awareness values).

## Non-compliant example
```hcl
resource "aws_opensearch_domain" "example" {
  domain_name    = "example-domain"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "r6g.large.search"
    instance_count = 3
    # No dedicated_master_enabled/count, no zone_awareness_enabled
  }
}
```

## Remediated example
```hcl
resource "aws_opensearch_domain" "example" {
  domain_name    = "example-domain"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type            = "r6g.large.search"
    instance_count            = 3
    zone_awareness_enabled    = true               # spread nodes across AZs
    zone_awareness_config {
      availability_zone_count = 3
    }
    dedicated_master_enabled = true                # required to use dedicated masters
    dedicated_master_type    = "r6g.large.search"
    dedicated_master_count   = 3                   # odd number >= 3 avoids split-brain
  }
}
```

## Remediation steps
1. Set `cluster_config.dedicated_master_enabled = true` and `dedicated_master_count = 3` (or another odd number ≥ 3) with an appropriate `dedicated_master_type`.
2. Set `zone_awareness_enabled = true` and configure `zone_awareness_config.availability_zone_count` (2 or 3) to match the number of subnets/AZs the domain spans.
3. Ensure `instance_count` (data nodes) is a multiple of the AZ count for even distribution.
4. Changing cluster topology on an existing domain triggers an AWS-managed blue/green deployment — plan for a maintenance window and confirm sufficient VPC subnet capacity across the target AZs.
5. Review cost impact: dedicated master nodes are billed separately and add to the monthly domain cost.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchDomainHA.py
- AWS docs: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/es-managedomains-dedicatedmasternodes.html
