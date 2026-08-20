# CKV_AWS_5: Ensure all data stored in the Elasticsearch is securely encrypted at rest
## Severity
**LOW** (score: 2.0/10)

Elasticsearch/OpenSearch domains frequently index sensitive application and log data, and disabling encryption at rest exposes that indexed data to disclosure if the underlying storage is accessed outside normal channels.

## Summary
This check ensures Amazon Elasticsearch Service / OpenSearch Service domains have encryption at rest enabled.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Elasticsearch::Domain` (CloudFormation); `aws_elasticsearch_domain`, `aws_opensearch_domain` (Terraform)

## Why it matters
Elasticsearch/OpenSearch domains commonly index and store large volumes of application logs, search indexes, and analytics data that can include PII, authentication events, or other sensitive fields — often duplicated from primary data stores specifically so they can be searched, which multiplies the number of places sensitive data lives. Without encryption at rest, the underlying EBS volumes backing the domain's data nodes store this data in plaintext; any exposure of the underlying storage (through a snapshot mishap, hardware decommissioning, or infrastructure-level compromise) would expose the indexed data directly. Encryption at rest is also a hard requirement in many compliance regimes for any data store holding regulated data, and — importantly for Elasticsearch/OpenSearch — **cannot be enabled after domain creation**, so getting this right at provisioning time avoids a costly re-index-and-migrate later.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck`:
- **CloudFormation:** inspects `Properties/EncryptionAtRestOptions/Enabled` on `AWS::Elasticsearch::Domain` — **PASS** if `true`, **FAIL** if `false` or absent.
- **Terraform:** inspects `encrypt_at_rest[0].enabled` on `aws_elasticsearch_domain` or `aws_opensearch_domain` — **PASS** if `true`, **FAIL** if the block/attribute is absent or `false` (encryption at rest is not enabled by default).

## Non-compliant example
```hcl
resource "aws_opensearch_domain" "example" {
  domain_name    = "example-domain"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "t3.small.search"
  }
  # encrypt_at_rest block not set -> unencrypted
}
```

## Remediated example
```hcl
resource "aws_opensearch_domain" "example" {
  domain_name    = "example-domain"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "t3.small.search"
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.opensearch.arn  # optional customer-managed key
  }
}
```

## Remediation steps
1. Add an `encrypt_at_rest { enabled = true }` block to the domain resource (or `Properties/EncryptionAtRestOptions/Enabled: true` in CloudFormation).
2. Note that encryption at rest requires a compatible instance type (most current-generation instance types support it; very old/small instance types may not) and, for OpenSearch/Elasticsearch, generally must be paired with node-to-node encryption and enforced HTTPS for a fully encrypted data path.
3. **Critical constraint:** encryption at rest cannot be toggled on an existing unencrypted domain — this requires creating a new encrypted domain and reindexing/migrating data (e.g., via snapshot restore or a reindex-from-remote operation), then repointing clients.
4. Plan a maintenance window for the migration and validate index compatibility (engine version, mappings) on the new domain before cutover.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchEncryption.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticsearchEncryption.py)
- [AWS OpenSearch/Elasticsearch encryption at rest documentation](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html)
