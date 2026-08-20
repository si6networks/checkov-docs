# CKV2_AWS_36: Ensure terraform is not sending SSM secrets to untrusted domains over HTTP
## Severity
**CRITICAL** (score: 9.0/10)

Fetching sensitive values over plaintext HTTP to untrusted domains and then storing them as unencrypted SSM parameters combines man-in-the-middle/spoofing exposure in transit with plaintext credential storage at rest, a direct secrets-exposure and supply-chain-tampering vector.

## Summary
This check flags Terraform configurations where a `data.http` data source is connected to an `aws_ssm_parameter` that is not of type `SecureString`, meaning a value fetched over plain HTTP (potentially from an untrusted external endpoint) is being stored unencrypted, or conversely where a `data.http` source exists disconnected from any SSM parameter at all (flagged for review).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/data types:** `aws_ssm_parameter`, `data.http`
- **Category:** Supply chain security

## Why it matters
The Terraform `http` data source performs an HTTP(S) GET request at plan/apply time and can be used to pull configuration values, secrets, or tokens from an external endpoint into your Terraform run — for example, fetching a database password or API token from an internal service and writing it into an SSM parameter. If that request is made over plain HTTP (not HTTPS) to an untrusted or unverified domain, the data in transit is exposed to network-level interception, man-in-the-middle tampering, or DNS spoofing — an attacker on the network path could substitute a malicious response, injecting attacker-controlled values into your infrastructure's configuration (a supply-chain compromise vector). And if the fetched value is then stored as a plain (non-`SecureString`) SSM parameter rather than an encrypted one, any sensitive data retrieved this way sits in Parameter Store in plaintext, compounding the exposure. This check calls out both halves of that risky pattern: an HTTP-sourced value flowing into an unencrypted parameter, and use of the `http` data source at all (which warrants review since it's inherently sourcing data from outside Terraform's normal, more auditable provider ecosystem).

## How Checkov evaluates this
This is a graph check (`HTTPNotSendingPasswords.json`) with two failure branches combined via `or`:
1. A `data.http` resource is connected to an `aws_ssm_parameter`, AND that parameter's `type` attribute is **not** `SecureString` (i.e., `not_equals SecureString`) → the `data.http`-sourced value is landing in a plaintext parameter.
2. A `data.http` resource exists with **no** connection at all to any `aws_ssm_parameter` → flagged, since an unconnected `http` data source pulling data over HTTP with no clear encrypted destination is itself treated as suspect/unreviewed usage.

In both branches the `data.http` resource is what's ultimately being filtered/flagged. Effectively: any use of `data.http` in the configuration triggers scrutiny, and it only cleanly passes when the fetched data flows into a `SecureString` SSM parameter (the encrypted-storage connection is the one combination the rule doesn't flag).

## Non-compliant example
```hcl
data "http" "external_token" {
  url = "http://internal-config.example.com/token"
}

resource "aws_ssm_parameter" "app_token" {
  name  = "/app/prod/token"
  type  = "String"
  value = data.http.external_token.response_body
}
```

## Remediated example
```hcl
data "http" "external_token" {
  url = "https://internal-config.example.com/token"

  request_headers = {
    Accept = "application/json"
  }
}

resource "aws_ssm_parameter" "app_token" {
  name   = "/app/prod/token"
  type   = "SecureString"
  value  = data.http.external_token.response_body
  key_id = aws_kms_key.ssm_key.arn
}
```

## Remediation steps
1. Ensure every `data.http` `url` uses `https://`, not `http://`, so the request itself is transport-encrypted and resistant to on-path tampering.
2. Only fetch data from domains you trust and control (or that are verified, pinned endpoints) — avoid using `http`/`https` data sources against arbitrary third-party URLs to source configuration that will become infrastructure state.
3. If the fetched value is sensitive (a token, password, or credential), store it in an `aws_ssm_parameter` with `type = "SecureString"` (or migrate to AWS Secrets Manager) rather than a plain `String`.
4. Consider whether the `http` data source is the right tool at all — for genuine secrets, prefer a dedicated secrets-management integration (e.g., fetching directly from AWS Secrets Manager, Vault, or a purpose-built Terraform provider) instead of a generic HTTP GET, which offers no authentication or integrity guarantees beyond TLS.
5. Remember that the response body of a `data.http` source is stored in Terraform state in plaintext regardless of the SSM parameter's type — ensure your Terraform state backend itself is encrypted and access-restricted.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/HTTPNotSendingPasswords.json)
- [Terraform `http` data source documentation](https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http)
