# CKV_AWS_83: Ensure Elasticsearch Domain enforces HTTPS
## Severity
**HIGH** (score: 8.0/10)

Failing to enforce HTTPS on an Elasticsearch/OpenSearch domain allows data (including search queries, results, and potentially credentials) to be transmitted in plaintext and intercepted on the network.

## Summary
This check fails when an Amazon Elasticsearch/OpenSearch Service domain does not enforce HTTPS-only access to its endpoint, meaning it may allow plaintext HTTP connections.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Elasticsearch::Domain` (CloudFormation), `aws_elasticsearch_domain`, `aws_opensearch_domain` (Terraform)
- **Check type:** resource

## Why it matters
Elasticsearch/OpenSearch domains typically hold indexed application data, logs, or search corpora — often including sensitive fields depending on what's indexed. If HTTPS is not enforced, the domain endpoint will accept plaintext HTTP requests, meaning query bodies, indexed documents, and any embedded authentication (e.g., basic-auth headers, or in less secure setups, API keys passed as query parameters) can be transmitted or intercepted in the clear by anyone positioned on the network path — including within the same VPC if network-layer isolation is imperfect. Given that these domains are frequently used as centralized log or SIEM-style stores, an interception of that traffic can itself expose downstream secrets or PII contained in the logs being shipped to the cluster.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck`:
- **CloudFormation:** inspects `Properties/DomainEndpointOptions/EnforceHTTPS`, expecting the base class default of `True`. Fails unless explicitly `true`.
- **Terraform:** inspects `domain_endpoint_options/[0]/enforce_https`, also expecting `true`, but with `missing_block_result=CheckResult.PASSED` — i.e., if the `domain_endpoint_options` block is entirely omitted, the check passes, since AWS's own default for `enforce_https` is `true` when the block isn't specified. It only fails when the block is present and `enforce_https` is explicitly set to `false`.

## Non-compliant example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "logs-domain"
  elasticsearch_version  = "7.10"

  domain_endpoint_options {
    enforce_https = false
  }
}
```

## Remediated example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "logs-domain"
  elasticsearch_version  = "7.10"

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
}
```

## Remediation steps
1. Set `enforce_https = true` explicitly (Terraform) or `EnforceHTTPS: true` (CloudFormation) within the domain's endpoint options — do so explicitly rather than relying on the default, for auditability.
2. Also set `tls_security_policy` to a modern minimum, such as `Policy-Min-TLS-1-2-2019-07`, to disallow outdated TLS versions/cipher suites.
3. Update any client applications, Logstash/Beats/Fluentd shippers, or Kibana/OpenSearch Dashboards configurations that currently connect over `http://` to use `https://` and trust the domain's certificate.
4. This change can typically be applied in place without domain replacement, though it will trigger a blue/green deployment on the underlying OpenSearch/Elasticsearch service, which can briefly affect availability during the configuration change window.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchDomainEnforceHTTPS.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ElasticsearchDomainEnforceHTTPS.py)
- [Amazon OpenSearch Service domain endpoint options](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/infrastructure-security.html)
