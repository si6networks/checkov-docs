# CKV_AWS_84: Ensure Elasticsearch Domain Logging is enabled
## Severity
**MEDIUM** (score: 5.0/10)

Missing Elasticsearch/OpenSearch domain logging removes the audit trail needed to detect unauthorized queries or administrative actions against a data store that often holds sensitive indexed data.

## Summary
This check fails when an Elasticsearch/OpenSearch Service domain does not have log publishing enabled and correctly configured (e.g., no enabled CloudWatch log destination for at least one log type).

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Elasticsearch::Domain`, `AWS::OpenSearchService::Domain` (CloudFormation), `aws_elasticsearch_domain`, `aws_opensearch_domain` (Terraform)
- **Check type:** resource

## Why it matters
Elasticsearch/OpenSearch domain logs (index slow logs, search slow logs, error logs, and audit logs) provide visibility into query patterns, indexing errors, and — critically for security — who accessed the cluster and what operations were performed, if audit logging is configured. Without any log publishing enabled, operators have no way to detect abnormal query volume (which could indicate data scraping/exfiltration), repeated authentication failures (which could indicate credential-stuffing against the domain's fine-grained access control), or cluster health issues that precede outages. Since these domains often serve as the backing store for centralized logging/SIEM pipelines themselves, a domain without its own logging is a blind spot precisely where an organization would expect the strongest audit posture.

## How Checkov evaluates this
- **CloudFormation (`ElasticsearchDomainLogging.py`):** Looks at `Properties.LogPublishingOptions`. If that dict has any entry whose value is a dict with `Enabled: true`, the check **PASSES**. If `LogPublishingOptions` is absent, empty, or none of its entries are enabled, it **FAILS**.
- **Terraform (`ElasticsearchDomainLogging.py`):** Looks at the `log_publishing_options` list attribute.
  - If `log_publishing_options` is absent or not a list → **FAIL**.
  - Take the first entry; if it's a dict with a `cloudwatch_log_group_arn` set:
    - If `enabled == [False]` explicitly → **FAIL**.
    - Otherwise (enabled true or unspecified, but ARN present) → **PASS**.
  - If no `cloudwatch_log_group_arn` is set at all → **FAIL**.

## Non-compliant example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "logs-domain"
  elasticsearch_version  = "7.10"
}
```

## Remediated example
```hcl
resource "aws_cloudwatch_log_group" "es_logs" {
  name = "/aws/opensearch/logs-domain/index-slow-logs"
}

resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "logs-domain"
  elasticsearch_version  = "7.10"

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es_logs.arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true
  }
}
```

## Remediation steps
1. Create a CloudWatch Log Group to receive domain logs.
2. Add a `log_publishing_options` block to the domain resource, referencing the log group ARN and setting `enabled = true`.
3. Add a resource-based CloudWatch Logs policy allowing the `es.amazonaws.com` (or `opensearchservice.amazonaws.com`) service principal to write to the log group — AWS requires this explicit permission for domain log delivery.
4. Consider enabling multiple log types where relevant: `INDEX_SLOW_LOGS`, `SEARCH_SLOW_LOGS`, `ES_APPLICATION_LOGS`, and — if using fine-grained access control — `AUDIT_LOGS` for the strongest security visibility.
5. This is a non-disruptive, in-place configuration change.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchDomainLogging.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticsearchDomainLogging.py)
- [Amazon OpenSearch Service log publishing](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createdomain-configure-slow-logs.html)
