# CKV2_AWS_52: Ensure AWS ElasticSearch/OpenSearch Fine-grained access control is enabled
## Severity
**LOW** (score: 2.0/10)

Disabling fine-grained access control on OpenSearch/Elasticsearch removes authentication and role-based authorization on the cluster, risking unauthorized read/write access to indexed data.

## Summary
This check fails when an Elasticsearch or OpenSearch domain does not have fine-grained access control enabled — specifically, neither `advanced_security_options.internal_user_database_enabled` nor `advanced_security_options.enabled` is set to `true`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_elasticsearch_domain`, `aws_opensearch_domain`

## Why it matters
Without fine-grained access control (FGAC), an OpenSearch/Elasticsearch domain's access model is coarse: authorization is typically enforced only at the IAM/resource-policy or network (VPC/security group) level, meaning any principal or network path that can reach the endpoint at all effectively has the same access to every index, document, and cluster-admin action. FGAC adds a role-based access control layer inside the cluster itself — you can scope specific users/roles to specific indices, specific document-level/field-level permissions, and separate cluster-admin operations from data-plane read/write, and it also enables the built-in Kibana/OpenSearch Dashboards multi-tenancy and audit logging of *which* internal user did *what*. Its absence means a single compromised IAM role or a security-group misconfiguration exposing the endpoint grants blanket access to all data in the cluster, with no internal authorization boundary and no per-user audit trail to fall back on.

## How Checkov evaluates this
This is a graph-based JSON policy with an `or` of two conditions:
- **PASS** if `advanced_security_options.internal_user_database_enabled` equals `"true"`, OR `advanced_security_options.enabled` equals `"true"`.
- **FAIL** if neither is set to `true` — i.e., the `advanced_security_options` block is absent or `enabled = false`.
- Both `aws_opensearch_domain` and the legacy `aws_elasticsearch_domain` resource types are checked identically.

## Non-compliant example
```hcl
resource "aws_opensearch_domain" "bad" {
  domain_name    = "example-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "r6g.large.search"
  }

  encrypt_at_rest {
    enabled = true
  }
  # no advanced_security_options block
}
```

## Remediated example
```hcl
resource "aws_opensearch_domain" "good" {
  domain_name    = "example-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "r6g.large.search"
  }

  encrypt_at_rest {
    enabled = true
  }

  # FGAC requires encryption at rest and node-to-node encryption
  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https = true
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true

    master_user_options {
      master_user_name     = "admin"
      master_user_password = var.opensearch_admin_password
    }
  }
}
```

## Remediation steps
1. Add an `advanced_security_options` block with `enabled = true`.
2. Choose an authentication backend: set `internal_user_database_enabled = true` with a `master_user_options` block (username/password) for the built-in internal user database, or integrate with IAM/SAML for identity federation instead.
3. FGAC requires `encrypt_at_rest.enabled = true` and `node_to_node_encryption.enabled = true` — enable both if not already set, and set `domain_endpoint_options.enforce_https = true`.
4. After enabling, define role mappings (via the OpenSearch Dashboards Security plugin or the `_plugins/_security` API) to scope specific users/roles to specific indices rather than relying on the master user for everyday access.
5. **Caution:** enabling FGAC on an existing, previously-unsecured domain is disruptive — it changes the authentication model and can require the domain to be recreated or cause a blue/green deployment depending on current configuration; plan a migration window and test index/role mappings before enabling in production.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/OpenSearchDomainHasFineGrainedControl.json
- AWS docs: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html
