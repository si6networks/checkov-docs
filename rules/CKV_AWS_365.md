# CKV_AWS_365: Ensure SES Configuration Set enforces TLS usage

## Severity
**MEDIUM** (score: 5.5/10)

Leaving TLS optional allows silent fallback to plaintext SMTP delivery, exposing potentially sensitive email content (password resets, MFA codes, PII) to passive network interception between mail servers.

## Summary
This check ensures that an `aws_ses_configuration_set` resource has its `delivery_options.tls_policy` set to `Require`, so that outbound emails sent through that configuration set are only delivered over TLS-encrypted connections.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Check type:** resource check
- **Entities:** `aws_ses_configuration_set`

## Why it matters
Amazon SES's `tls_policy` setting controls whether the message must be delivered over an encrypted (TLS) connection to the receiving mail server. The default/`Optional` setting attempts TLS but silently falls back to unencrypted SMTP if the receiving server doesn't support or negotiate TLS. Email frequently carries sensitive content — password reset links, MFA codes, PII, financial statements, internal communications — and if delivery falls back to plaintext SMTP, the message becomes vulnerable to interception or tampering by any network intermediary between the sending and receiving mail servers (a classic STARTTLS-stripping / passive-eavesdropping risk). Setting the policy to `Require` ensures SES will refuse to deliver (bouncing the message) rather than silently downgrading to plaintext, giving senders a clear signal to fix delivery issues rather than an invisible security regression.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) that inspects `delivery_options[0].tls_policy`. The expected value is the literal string `"Require"`. If the `delivery_options` block is missing entirely, the check treats this as a **FAIL** (`missing_block_result=CheckResult.FAILED`) — i.e., omitting the block is not neutral, it fails by default since the AWS default is `Optional`.

## Non-compliant example
```hcl
resource "aws_ses_configuration_set" "transactional" {
  name = "transactional-emails"

  delivery_options {
    tls_policy = "Optional"
  }
}
```

## Remediated example
```hcl
resource "aws_ses_configuration_set" "transactional" {
  name = "transactional-emails"

  delivery_options {
    tls_policy = "Require"
  }
}
```

## Remediation steps
1. Add (or update) the `delivery_options` block on the `aws_ses_configuration_set` resource with `tls_policy = "Require"`.
2. Monitor SES bounce/complaint metrics after the change — recipients whose mail servers genuinely cannot negotiate TLS will now bounce instead of receiving plaintext mail; this is the intended trade-off, but confirm it doesn't break delivery to legitimate destinations you depend on.
3. Ensure any application code sending mail actually references this configuration set (via the `X-SES-CONFIGURATION-SET` header or API parameter) — setting the policy on an unused configuration set provides no protection.
4. No resource replacement is required; this is a mutable property.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SesConfigurationSetDefinesTLS.py
- AWS docs: https://docs.aws.amazon.com/ses/latest/dg/configure-tls-requirement.html
