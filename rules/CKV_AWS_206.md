# CKV_AWS_206: Ensure API Gateway Domain uses a modern security Policy
## Severity
**HIGH** (score: 7.0/10)

An API Gateway custom domain pinned to an outdated TLS security policy permits weaker cipher suites and protocol versions, increasing the risk of downgrade or interception attacks against a typically internet-facing API endpoint.

## Summary
Ensures that an API Gateway custom domain name is configured with a modern TLS security policy, rather than an outdated policy that allows weaker TLS versions/ciphers.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_api_gateway_domain_name` — inspects the `security_policy` attribute.

## Why it matters
The `security_policy` on an API Gateway custom domain determines the minimum TLS protocol version and cipher suites accepted from clients connecting to your API. An outdated or unset security policy can allow negotiation down to older TLS versions (e.g., TLS 1.0/1.1) which have known cryptographic weaknesses (e.g., BEAST, POODLE-adjacent issues, weak cipher suites) and are explicitly disallowed under PCI-DSS 4.0 and other compliance frameworks. Allowing legacy TLS:
- Increases exposure to protocol-downgrade and man-in-the-middle attacks against clients that haven't been updated to negotiate stronger versions.
- Fails audits that specifically require TLS 1.2+ (or TLS 1.3) minimums for any endpoint handling sensitive data or authentication tokens.
- Provides a weaker guarantee of confidentiality/integrity for API traffic that may carry credentials, PII, or financial data.

## How Checkov evaluates this
`APIGatewayDomainNameTLS` is a `BaseResourceValueCheck` with a `get_expected_values()` allow-list rather than a single value:
- PASS if `security_policy` is one of: `TLS_1_2`, `SecurityPolicy_TLS12_2018_EDGE`, `SecurityPolicy_TLS12_PFS_2025_EDGE`, `SecurityPolicy_TLS13_1_2_2021_06`, `SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09`, `SecurityPolicy_TLS13_1_2_PQ_2025_09`, `SecurityPolicy_TLS13_1_3_2025_09`, `SecurityPolicy_TLS13_1_3_FIPS_2025_09`, `SecurityPolicy_TLS13_2025_EDGE`.
- FAIL if `security_policy` is unset or set to any other value (e.g., legacy default policies that permit TLS 1.0).

## Non-compliant example
```hcl
resource "aws_api_gateway_domain_name" "api_domain" {
  domain_name              = "api.example.com"
  regional_certificate_arn = aws_acm_certificate.api.arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }
  # No security_policy set -> FAILS CKV_AWS_206 (defaults to legacy TLS policy)
}
```

## Remediated example
```hcl
resource "aws_api_gateway_domain_name" "api_domain" {
  domain_name              = "api.example.com"
  regional_certificate_arn = aws_acm_certificate.api.arn
  security_policy          = "TLS_1_2"   # fix: modern minimum TLS version

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}
```

## Remediation steps
1. Set `security_policy` explicitly to `TLS_1_2` at minimum, or a newer `SecurityPolicy_TLS13_*` value if your client base supports TLS 1.3.
2. Confirm all client applications/SDKs that connect to the API domain support the chosen minimum TLS version before rollout, to avoid breaking legacy clients.
3. This setting applies only to `REGIONAL` and `PRIVATE` endpoint types with a custom domain — `EDGE` endpoint types have their own set of `EDGE`-suffixed policy values (`SecurityPolicy_TLS12_2018_EDGE`, etc.).
4. Updating `security_policy` on an existing domain is an in-place update (no replacement/downtime expected), but validate with a canary before wide rollout in case of legacy client breakage.
5. Pair this with periodic review as AWS introduces newer named policies (e.g., TLS 1.3 variants) to keep pace with evolving best practice.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayDomainNameTLS.py
- AWS docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html
