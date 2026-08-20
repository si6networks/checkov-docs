# CKV_AWS_259: Ensure CloudFront response header policy enforces Strict Transport Security

## Severity
**MEDIUM** (score: 6.0/10)

Missing or weak Strict-Transport-Security enforcement on CloudFront responses leaves the initial connection (or lapsed sessions) open to HTTPS-downgrade/SSL-stripping by an on-path attacker, a meaningful but conditional transport-security weakening rather than a fully open exposure.

## Summary
This check ensures that a CloudFront response headers policy has a fully and correctly configured `strict_transport_security` block — enabled with a sufficiently long max-age, subdomain inclusion, override, and preload — so that the HSTS header is actually enforced on responses.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_cloudfront_response_headers_policy`

## Why it matters
The `Strict-Transport-Security` (HSTS) header instructs browsers to only ever contact the origin over HTTPS for a specified duration, closing off a significant class of attack: without HSTS, a user's very first request (or any request following an expired/absent HSTS record) can be intercepted by an on-path attacker and downgraded from HTTPS to HTTP via SSL-stripping techniques, letting the attacker read or tamper with traffic that the user believes is encrypted. A short `max-age`, missing `includeSubDomains`, or missing `preload` each weaken this protection in a specific way: a short max-age means the protection lapses quickly if the user doesn't revisit the site often; missing `includeSubDomains` leaves subdomains open to downgrade attacks even if the main domain is protected; and missing `preload` means the very first connection ever made to the domain (before any HSTS header has been received) is still vulnerable, since preload lists (baked into browsers) are the only way to close that initial gap.

## How Checkov evaluates this
The check walks:

```
security_headers_config/[0]/strict_transport_security/[0]/{access_control_max_age_sec, include_subdomains, preload, override}
```

Evaluated in order — the check **FAILs** immediately if any of the following is true:
1. `security_headers_config` or `strict_transport_security` block is missing entirely.
2. `access_control_max_age_sec` is not set, or is set but resolves to less than `31536000` (1 year in seconds).
3. `include_subdomains` is not set to `true`.
4. `preload` is not set to `true`.
5. `override` is not set to `true`.

**PASS**: only if all four conditions (max-age ≥ 1 year, `include_subdomains = true`, `preload = true`, `override = true`) are satisfied.

## Non-compliant example
```hcl
resource "aws_cloudfront_response_headers_policy" "example" {
  name = "example-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 3600   # far too short (1 hour)
      include_subdomains          = false
      preload                     = false
      override                    = true
    }
  }
}
```

## Remediated example
```hcl
resource "aws_cloudfront_response_headers_policy" "example" {
  name = "example-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000  # <-- 1 year minimum
      include_subdomains          = true      # <-- added
      preload                     = true      # <-- added
      override                    = true
    }
  }
}
```

## Remediation steps
1. Set `access_control_max_age_sec` to at least `31536000` (one year) — many organizations use `63072000` (two years) to comfortably exceed browser preload-list requirements.
2. Set `include_subdomains = true` so the HSTS policy also protects all subdomains — only omit this if you have subdomains that must remain HTTP-accessible (rare, and itself a risk worth reviewing).
3. Set `preload = true` and separately submit the domain to the [HSTS preload list](https://hstspreload.org/) if you want the very-first-connection protection browsers provide for preloaded domains (note: submitting to the preload list is largely irreversible in practice — removal from browser preload lists takes a long time to propagate, so only preload domains you're certain will stay HTTPS-only long-term).
4. Set `override = true` so this response header policy's HSTS setting takes precedence over any HSTS header the origin itself might return, ensuring consistent enforcement at the CDN edge.
5. Apply and verify via `curl -I` against a CloudFront distribution using this response headers policy that the `Strict-Transport-Security` header is present with the expected directives.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudFrontResponseHeaderStrictTransportSecurity.py)
- [Terraform: aws_cloudfront_response_headers_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_response_headers_policy)
- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
