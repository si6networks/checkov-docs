# CKV_AWS_220: Ensure that CloudSearch is using https
## Severity
**HIGH** (score: 7.5/10)

Failing to enforce HTTPS on a CloudSearch domain permits plaintext HTTP requests and responses, fully exposing search queries and potentially sensitive indexed data to network eavesdroppers.

## Summary
This check ensures that an Amazon CloudSearch domain (`aws_cloudsearch_domain`) enforces HTTPS for all requests to its search/document endpoints via the `enforce_https` setting.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_cloudsearch_domain`

## Why it matters
CloudSearch domains, by default, can accept both HTTP and HTTPS requests to their search and document (indexing) endpoints. If HTTPS is not enforced, clients (or misconfigured integrations) can send search queries and — more critically — document upload/indexing requests over plaintext HTTP. Search queries can contain sensitive user input (e.g. queries derived from customer search terms, account identifiers embedded in filters), and document upload requests can contain the actual data being indexed, which may include confidential or regulated content. Sending either over plaintext HTTP exposes that data to interception by anyone able to observe network traffic along the path, and also permits request tampering (e.g. an attacker injecting or altering indexed documents) since there is no transport-layer integrity protection on unencrypted HTTP.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute path `endpoint_options/[0]/enforce_https`:
- The expected value is `true`.
- If `enforce_https` is set to `true`, the check **PASSES**.
- If it is `false` or absent, the check **FAILS** (default missing-block behavior).

## Non-compliant example
```hcl
resource "aws_cloudsearch_domain" "example" {
  name = "example-domain"

  endpoint_options {
    enforce_https       = false
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
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
1. Add or update the `endpoint_options` block on the `aws_cloudsearch_domain` resource to set `enforce_https = true`.
2. Combine with `tls_security_policy = "Policy-Min-TLS-1-2-2019-07"` (see CKV_AWS_218) to enforce both HTTPS and a modern TLS floor.
3. Update any clients, scripts, or SDK configurations that currently call the domain's endpoints over plain `http://` to use `https://` instead, since HTTP requests will be rejected once enforced.
4. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudsearchDomainEnforceHttps.py)
- [AWS CloudSearch: Configuring a Domain (endpoint options)](https://docs.aws.amazon.com/cloudsearch/latest/developerguide/configuring-domains.html)
