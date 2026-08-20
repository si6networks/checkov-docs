# CKV_GIT_2: Ensure GitHub repository webhooks are using HTTPS
## Severity
**HIGH** (score: 7.0/10)

Disabling SSL certificate verification on a repository webhook allows a man-in-the-middle attacker to intercept or tamper with webhook payloads and signing secrets in transit.

## Summary
This check ensures that GitHub repository webhooks are configured to verify SSL/TLS (i.e., do not disable certificate validation) when delivering payloads to their target endpoint.

## Applicability
Applies to Terraform configurations using the `github` provider, specifically the `github_repository_webhook` resource, at the `configuration[0].insecure_ssl` attribute.

## Why it matters
GitHub webhooks deliver event payloads (which can include commit metadata, PR content, or in misconfigured setups, sensitive repository data) to an external URL over HTTP/HTTPS. The `insecure_ssl` setting controls whether GitHub validates the destination server's TLS certificate. When `insecure_ssl` is enabled (set to `"1"`/true), GitHub will deliver the webhook payload even if the receiving endpoint presents an invalid, expired, self-signed, or otherwise untrusted certificate. This defeats certificate-based authentication of the endpoint and exposes the webhook payload to man-in-the-middle interception or spoofing — an attacker who can intercept traffic (e.g., via DNS hijack, ARP spoofing on a compromised network, or a rogue CA) could impersonate the legitimate receiver, capture the payload, or inject a fraudulent one, potentially triggering unintended downstream automation (CI triggers, deployments, notifications).

## How Checkov evaluates this
`WebhookInsecureSsl` is a `BaseResourceValueCheck` that inspects `configuration[0].insecure_ssl`:
- **PASS** if the attribute is absent entirely (`missing_block_result=PASSED`, since the GitHub provider/API default for `insecure_ssl` is `false`/secure).
- **PASS** if `insecure_ssl` is explicitly `false`.
- **FAIL** if `insecure_ssl` is explicitly `true` (or `"1"`).

## Non-compliant example
```hcl
resource "github_repository_webhook" "ci_notify" {
  repository = "payments-service"

  configuration {
    url          = "https://ci.internal.example.com/hooks/github"
    content_type = "json"
    insecure_ssl = true   # disables TLS certificate validation
  }

  events = ["push", "pull_request"]
}
```

## Remediated example
```hcl
resource "github_repository_webhook" "ci_notify" {
  repository = "payments-service"

  configuration {
    url          = "https://ci.internal.example.com/hooks/github"
    content_type = "json"
    insecure_ssl = false  # fix: enforce certificate validation
  }

  events = ["push", "pull_request"]
}
```

## Remediation steps
1. Set `insecure_ssl = false` explicitly, or simply omit the attribute (the safe default) in every `github_repository_webhook` resource.
2. If the webhook target currently uses a self-signed or invalid certificate, fix the target's certificate (e.g., issue a proper certificate via Let's Encrypt or your internal CA) rather than disabling validation.
3. Ensure the webhook target URL uses `https://`, not `http://`, since `insecure_ssl` only pertains to certificate validation, not transport encryption itself.
4. Audit any existing webhooks for `insecure_ssl = true` via `terraform plan`/state inspection or the GitHub API, and rotate/update them.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/github/WebhookInsecureSsl.py)
- [Terraform GitHub provider: github_repository_webhook](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository_webhook)
