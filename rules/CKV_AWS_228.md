# CKV_AWS_228: Verify Elasticsearch domain is using an up to date TLS policy

## Severity
**HIGH** (score: 7.5/10)

An outdated TLS security policy permits legacy TLS versions and weak cipher suites on the domain's HTTPS endpoint, exposing search data, credentials, and query content to interception or downgrade attacks in transit.

## Summary
This check ensures that an AWS Elasticsearch/OpenSearch domain's HTTPS endpoint is configured to require a modern, secure TLS security policy rather than an outdated or default one.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_elasticsearch_domain`, `aws_opensearch_domain`

## Why it matters
The `tls_security_policy` setting on an Elasticsearch/OpenSearch domain controls which TLS protocol versions and cipher suites clients are allowed to use when connecting to the domain's HTTPS endpoint. Older policies permit TLS 1.0/1.1 and weaker cipher suites that are vulnerable to known attacks (e.g. BEAST, POODLE, and various padding-oracle and downgrade attacks) and are commonly flagged in PCI-DSS, HIPAA, and SOC 2 audits. Domains left on the AWS default policy — or with no policy pinned at all — may unexpectedly allow legacy clients to negotiate weak TLS, exposing search data, credentials, and query content in transit to interception or tampering. Since Elasticsearch/OpenSearch domains often store logs, application data, or PII, enforcing a strict minimum TLS version and preferring forward-secrecy cipher suites materially reduces the domain's transit-layer attack surface.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `domain_endpoint_options[0].tls_security_policy`.
- **PASS** if the value is one of the accepted policies: `Policy-Min-TLS-1-2-2019-07` or `Policy-Min-TLS-1-2-PFS-2023-10` (the newer policy that adds Perfect Forward Secrecy cipher suites).
- **FAIL** if the value is missing, or set to anything else (e.g. the older `Policy-Min-TLS-1-0-2019-07`).
- The check's preferred/"expected" value used for auto-remediation guidance is `Policy-Min-TLS-1-2-PFS-2023-10`.

## Non-compliant example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name = "app-logs"

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy  = "Policy-Min-TLS-1-0-2019-07"
  }
}
```

## Remediated example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name = "app-logs"

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy  = "Policy-Min-TLS-1-2-PFS-2023-10"
  }
}
```

## Remediation steps
1. Add or update the `domain_endpoint_options` block on the `aws_elasticsearch_domain`/`aws_opensearch_domain` resource.
2. Set `tls_security_policy` to `"Policy-Min-TLS-1-2-PFS-2023-10"` (preferred) or at minimum `"Policy-Min-TLS-1-2-2019-07"`.
3. Also set `enforce_https = true` in the same block so plaintext HTTP is rejected outright (not itself covered by this check, but a closely related setting).
4. Confirm all clients connecting to the domain support TLS 1.2+ before rolling this out, since older clients negotiating only TLS 1.0/1.1 will be rejected after the change.
5. Applying this change updates the domain in place; AWS applies it without requiring a new domain, but processing can take some time on the domain (check `apply_immediately`/domain processing state if using `aws_opensearch_domain`).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchTLSPolicy.py)
- [AWS OpenSearch Service: Off-cluster domain HTTPS/TLS policies](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/infrastructure-security.html)
