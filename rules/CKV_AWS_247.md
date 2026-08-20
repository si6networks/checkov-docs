# CKV_AWS_247: Ensure all data stored in the Elasticsearch is encrypted with a CMK

## Severity
**LOW** (score: 2.0/10)

Elasticsearch/OpenSearch domains commonly hold logs, application data, or PII, and failing to encrypt that data at rest with a customer-managed key leaves a sensitive data store's persisted data inadequately protected.

## Summary
This check ensures that Elasticsearch/OpenSearch domains have encryption-at-rest configured using a customer-managed KMS key, rather than left unencrypted or relying only on an AWS-owned key.

## Applicability
- **Framework:** Terraform
- **Resource types:** `aws_elasticsearch_domain`, `aws_opensearch_domain`

## Why it matters
Elasticsearch/OpenSearch domains commonly index application logs, user records, search indices built from production databases, or full-text copies of sensitive documents. Without encryption at rest, the underlying EBS volumes, snapshots, and any data written to disk (including swap and temp files used during query execution) are stored in plaintext — if the underlying storage or a snapshot is ever exposed (e.g. through misconfigured snapshot repository permissions, or physical media disposal issues on AWS's side), the entire dataset is directly readable. Using a customer-managed KMS key (rather than no encryption, or the default AWS-managed key) additionally provides key-level access control and CloudTrail auditability of every decrypt operation, letting security teams detect and immediately revoke access if the domain or its snapshots are ever compromised.

## How Checkov evaluates this
The check inspects the nested attribute path:

```
encrypt_at_rest/[0]/kms_key_id
```

with an expected value of `ANY_VALUE`.

- **PASS**: `encrypt_at_rest { kms_key_id = "<any value>" }` is set.
- **FAIL**: the `encrypt_at_rest` block is missing, or `kms_key_id` is absent/empty (this also fails if `encrypt_at_rest.enabled` is true but no `kms_key_id` is specified, since the path requires the key attribute itself to be present).

## Non-compliant example
```hcl
resource "aws_elasticsearch_domain" "example" {
  domain_name    = "example-logs"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "r6g.large.elasticsearch"
  }

  encrypt_at_rest {
    enabled = true
    # kms_key_id not specified
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "es_cmk" {
  description         = "CMK for Elasticsearch domain encryption at rest"
  enable_key_rotation = true
}

resource "aws_elasticsearch_domain" "example" {
  domain_name           = "example-logs"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "r6g.large.elasticsearch"
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.es_cmk.arn   # <-- added
  }
}
```

## Remediation steps
1. Create a customer-managed KMS key dedicated to the search domain (or reuse an existing data-tier CMK per your key strategy).
2. Add `encrypt_at_rest { enabled = true; kms_key_id = <cmk-arn> }` to the domain resource.
3. **Important:** encryption at rest cannot be enabled on an existing domain in place — for `aws_elasticsearch_domain`/`aws_opensearch_domain`, changing this setting forces resource replacement (a new domain with data reindexed/restored from snapshot). Plan for a migration window and data reindex/snapshot-restore.
4. Ensure the OpenSearch/Elasticsearch service role has `kms:Decrypt` and `kms:CreateGrant` permissions on the CMK.
5. For new domains, set this from day one to avoid the future migration cost.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchEncryptionWithCMK.py)
- [Terraform: aws_elasticsearch_domain](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain)
- [AWS: Encryption of data at rest for Amazon OpenSearch Service](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html)
