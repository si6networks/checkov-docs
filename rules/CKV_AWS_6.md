# CKV_AWS_6: Ensure all Elasticsearch has node-to-node encryption enabled
## Severity
**HIGH** (score: 7.5/10)

Without node-to-node encryption, traffic between Elasticsearch/OpenSearch cluster nodes travels in plaintext, allowing interception of indexed data (which often includes logs or sensitive records) by anyone with network access to the cluster's VPC segment.

## Summary
This check verifies that a multi-node Elasticsearch/OpenSearch domain has node-to-node (in-transit) encryption enabled, so that data replicated and communicated between the cluster's data nodes is encrypted rather than sent in plaintext.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::Elasticsearch::Domain`, property `Properties/NodeToNodeEncryptionOptions/Enabled`.
- **Terraform**: `aws_elasticsearch_domain` and `aws_opensearch_domain` resources, block `node_to_node_encryption { enabled = ... }`.

## Why it matters
Elasticsearch/OpenSearch clusters replicate indices and shard data between nodes over the network for redundancy and query distribution. Without node-to-node encryption, this internal traffic — which can include the full contents of indexed documents (potentially containing PII, logs with credentials, or other sensitive search data) — travels in plaintext within the VPC. Any entity able to intercept traffic on that network segment (a compromised instance in the same VPC, a misconfigured security group, or a malicious insider with network access) could sniff sensitive data at rest between shard replicas. This is particularly relevant for regulated data (PCI, HIPAA) where in-transit encryption of internal cluster traffic, not just client-facing HTTPS, is often a compliance requirement.

## How Checkov evaluates this
**CloudFormation** (`BaseResourceValueCheck`): checks `Properties/NodeToNodeEncryptionOptions/Enabled` is `true`.

**Terraform** (custom `BaseResourceCheck` with special-case logic):
1. Reads `cluster_config[0]`. If there's no cluster config or no `instance_count` specified, the check PASSES (can't determine risk, treated as not applicable/default).
2. If `instance_count` cannot be resolved to an int, returns `UNKNOWN`.
3. **Single-node clusters (`instance_count <= 1`) automatically PASS** — node-to-node encryption is only meaningful when there's more than one node to replicate between.
4. For multi-node clusters, it then checks `node_to_node_encryption[0].enabled`: if not a boolean, returns `UNKNOWN`; if `true`, PASSES; otherwise FAILS.

This means the check's real target is genuinely multi-node clusters, which is exactly the scenario where node-to-node traffic exists and needs protecting.

## Non-compliant example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "app-logs"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type  = "r6g.large.elasticsearch"
    instance_count = 3
  }
  # no node_to_node_encryption block -> non-compliant for a 3-node cluster
}
```

## Remediated example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "app-logs"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type  = "r6g.large.elasticsearch"
    instance_count = 3
  }

  node_to_node_encryption {
    enabled = true            # fixed
  }

  encrypt_at_rest {
    enabled = true
  }
}
```

## Remediation steps
1. Add a `node_to_node_encryption { enabled = true }` block to the `aws_elasticsearch_domain`/`aws_opensearch_domain` resource (or the equivalent `NodeToNodeEncryptionOptions` in CloudFormation).
2. **Caveat**: node-to-node encryption cannot be enabled on an existing domain in-place in all cases without triggering a "blue/green" deployment (AWS re-provisions the domain behind the scenes); plan for a maintenance window and verify via a snapshot/backup beforehand.
3. Also enable `encrypt_at_rest` (data-at-rest encryption) and enforce HTTPS-only (`domain_endpoint_options.enforce_https = true`) for full-stack encryption coverage.
4. Single-node/dev domains are not flagged by this check since there's no inter-node traffic, but consider enabling it anyway for consistency between dev and prod configs.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticsearchNodeToNodeEncryption.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchNodeToNodeEncryption.py)
- [AWS: Node-to-node encryption for Amazon OpenSearch Service](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html)
