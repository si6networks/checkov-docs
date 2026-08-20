# CKV_AWS_234: Verify logging preference for ACM certificates

## Severity
**LOW** (score: 2.0/10)

Disabling Certificate Transparency logging removes a detective control that helps domain owners spot fraudulently or mistakenly issued certificates, but it does not itself create an active attack path.

## Summary
This check ensures that `aws_acm_certificate` resources have Certificate Transparency (CT) logging enabled, rather than opted out.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_acm_certificate`

## Why it matters
Certificate Transparency is an industry-wide mechanism (mandated by all major browsers for publicly trusted TLS certificates) in which every issued certificate is recorded in public, append-only CT logs. This allows domain owners to detect certificates that were mis-issued — for example, by a compromised or careless Certificate Authority, or through a fraudulent domain-validation bypass — before they can be used maliciously against the domain. If CT logging is explicitly disabled for a certificate, that certificate will not appear in public CT logs, and modern browsers will typically reject unlogged public certificates outright or display trust errors, causing user-facing connection failures. Beyond the reliability angle, disabling CT logging removes a key transparency/detection control: it becomes harder for a domain owner to notice if someone managed to issue an unauthorized certificate for their domain, since that certificate would not surface in the log-monitoring tools organizations use (e.g. `crt.sh` watchers) to catch impersonation attempts.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `options[0].certificate_transparency_logging_preference`.
- If the `options` block (or the key within it) is **absent entirely**, the check treats this as a PASS (`missing_block_result=CheckResult.PASSED`) — AWS's own default for this setting is `ENABLED`.
- **PASS** if the value is explicitly `"ENABLED"`.
- **FAIL** if the value is explicitly `"DISABLED"`.

## Non-compliant example
```hcl
resource "aws_acm_certificate" "cert" {
  domain_name       = "app.example.com"
  validation_method = "DNS"

  options {
    certificate_transparency_logging_preference = "DISABLED"
  }
}
```

## Remediated example
```hcl
resource "aws_acm_certificate" "cert" {
  domain_name       = "app.example.com"
  validation_method = "DNS"

  options {
    certificate_transparency_logging_preference = "ENABLED"
  }
}
```

## Remediation steps
1. Remove the `options` block entirely (accepting the AWS default of `ENABLED`), or set `certificate_transparency_logging_preference = "ENABLED"` explicitly.
2. If a private/internal-only certificate genuinely needs to avoid public CT logging (e.g. to avoid revealing internal-only hostnames publicly), consider whether a private CA (AWS Certificate Manager Private CA / ACM PCA) is more appropriate than a public ACM certificate with logging disabled, since disabling CT on a public cert is generally discouraged by browser vendors.
3. Changing this setting on an existing certificate typically requires reissuing the certificate (AWS re-issues to apply logging preference changes), so plan for a brief certificate rotation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ACMCertSetLoggingPreference.py)
- [AWS Certificate Manager: Opting out of Certificate Transparency logging](https://docs.aws.amazon.com/acm/latest/userguide/acm-bestpractices.html#best-practices-transparency)
