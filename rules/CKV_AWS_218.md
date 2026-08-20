# CKV_AWS_218: Ensure that CloudSearch is using latest TLS
## Severity
**HIGH** (score: 7.0/10)

Allowing a CloudSearch domain to negotiate below TLS 1.2 exposes search queries and indexed data in transit to interception or downgrade attacks against a potentially internet-reachable endpoint.

## Summary
This check ensures that an Amazon CloudSearch domain (`aws_cloudsearch_domain`) enforces the modern TLS security policy `Policy-Min-TLS-1-2-2019-07` for its HTTPS endpoint.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_cloudsearch_domain`

## Why it matters
CloudSearch domains expose a search endpoint that clients query over HTTPS. The `tls_security_policy` setting controls the minimum TLS protocol version and cipher suites the endpoint will accept. If this is left at an older/default policy that permits TLS versions below 1.2, connections can be negotiated using protocols (TLS 1.0/1.1) with known weaknesses — susceptibility to protocol downgrade attacks, weaker cipher support, and non-compliance with standards like PCI-DSS which require TLS 1.2 or higher. Since CloudSearch domains are often used to serve or accept search queries containing user or application data, allowing weak TLS versions increases the risk of traffic interception or downgrade attacks against a channel that may carry sensitive query content or search result data.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute path `endpoint_options/[0]/tls_security_policy`:
- The expected value is exactly `"Policy-Min-TLS-1-2-2019-07"`.
- If `tls_security_policy` is set to this value, the check **PASSES**.
- If it is set to any other value (e.g. an older policy) or is absent, the check **FAILS** (default missing-block behavior for `BaseResourceValueCheck`).

## Non-compliant example
```hcl
resource "aws_cloudsearch_domain" "example" {
  name = "example-domain"

  endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
}
```

## Remediated example
```hcl
resource "aws_cloudsearch_domain" "example" {
  name = "example-domain"

  endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
}
```

## Remediation steps
1. Add or update the `endpoint_options` block on the `aws_cloudsearch_domain` resource to set `tls_security_policy = "Policy-Min-TLS-1-2-2019-07"`.
2. Combine this with `enforce_https = true` (see CKV_AWS_220) so that HTTPS is both required and using a strong TLS floor.
3. Verify any client SDKs or HTTP libraries querying the CloudSearch endpoint support TLS 1.2, since older clients will be rejected after this change.
4. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudsearchDomainTLS.py)
- [AWS CloudSearch: Configuring a Domain (endpoint options)](https://docs.aws.amazon.com/cloudsearch/latest/developerguide/configuring-domains.html)
