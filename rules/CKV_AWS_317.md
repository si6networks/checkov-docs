# CKV_AWS_317: Ensure Elasticsearch Domain Audit Logging is enabled

## Severity
**MEDIUM** (score: 5.0/10)

Disabling audit logging on an Elasticsearch/OpenSearch domain removes the record of authentication and data-access events on a data store that frequently holds sensitive, searchable data, undermining detection and forensics.

## Summary
This check ensures Amazon Elasticsearch/OpenSearch Service domains have audit logging enabled, so that fine-grained access-control events (authentication, authorization decisions, index/document access) are recorded.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** Terraform and CloudFormation
- **Resource types:** `aws_elasticsearch_domain`, `aws_opensearch_domain` (Terraform); `AWS::Elasticsearch::Domain`, `AWS::OpenSearchService::Domain` (CloudFormation)

## Why it matters
Audit logs are the primary forensic record of who accessed what data in an Elasticsearch/OpenSearch domain and what actions they took — including failed authentication attempts, permission denials, and index/document-level read/write operations under fine-grained access control. Without audit logging enabled, a security team investigating a suspected data breach, insider threat, or unauthorized query against a domain holding potentially sensitive search indices has no way to reconstruct the sequence of events. This directly weakens accountability and audit controls (NIST 800-53 AU-2, AU-3, AU-12) and typically also fails compliance frameworks (PCI-DSS, HIPAA, SOC 2) that require access logging for systems handling regulated data.

## How Checkov evaluates this
**Terraform:** Iterates the `log_publishing_options` blocks on `aws_elasticsearch_domain`/`aws_opensearch_domain`, looking for an entry where `log_type == "AUDIT_LOGS"` and `enabled` is truthy. **PASS** only if such an entry is found; **FAIL** otherwise (including when `log_publishing_options` is absent, or only CloudWatch/ES application/search-slow logs are configured without an `AUDIT_LOGS` entry).

**CloudFormation:** A `BaseResourceValueCheck` inspecting `Properties.LogPublishingOptions.AUDIT_LOGS.Enabled` — **PASS** if set truthy, **FAIL** otherwise.

Note: audit logging in Elasticsearch/OpenSearch additionally requires fine-grained access control to be enabled on the domain; Checkov's check here only verifies the log-publishing configuration itself.

## Non-compliant example
```hcl
resource "aws_opensearch_domain" "example" {
  domain_name    = "example-domain"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "r6g.large.search"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = var.master_password
    }
  }
  # No log_publishing_options -> no AUDIT_LOGS entry
}
```

## Remediated example
```hcl
resource "aws_cloudwatch_log_group" "audit_logs" {
  name = "/aws/opensearch/example-domain/audit-logs"
}

resource "aws_opensearch_domain" "example" {
  domain_name    = "example-domain"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "r6g.large.search"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = var.master_password
    }
  }

  log_publishing_options {                             # added: audit logging
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.audit_logs.arn
    log_type                 = "AUDIT_LOGS"
    enabled                  = true
  }
}
```

## Remediation steps
1. Ensure `advanced_security_options.enabled = true` (fine-grained access control) — audit logs require this to be meaningful, as they log FGAC decisions.
2. Create a dedicated CloudWatch Log Group for audit logs.
3. Add a `log_publishing_options` block with `log_type = "AUDIT_LOGS"`, `enabled = true`, and `cloudwatch_log_group_arn` pointing at that log group.
4. Attach a resource-based policy to the log group permitting the `es.amazonaws.com` (or `opensearchservice.amazonaws.com`) service principal to write log events (`logs:PutLogEvents`, `logs:CreateLogStream`).
5. Configure appropriate log retention on the CloudWatch Log Group to balance audit requirements against storage cost.
6. This change can typically be applied in-place without domain replacement, though domain configuration changes can trigger a blue/green deployment with a brief period of reduced capacity.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchDomainAuditLogging.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticsearchDomainAuditLogging.py
- AWS docs: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html
