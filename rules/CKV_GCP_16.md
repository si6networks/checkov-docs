# CKV_GCP_16: Ensure that DNSSEC is enabled for Cloud DNS
## Severity
**MEDIUM** (score: 5.0/10)

Without DNSSEC, a public zone's records can be spoofed or tampered with via cache poisoning, enabling redirection of traffic, but exploitation requires an active on-path or off-path DNS attack rather than direct data exposure.

## Summary
This check fails when a public `google_dns_managed_zone` does not have DNSSEC (`dnssec_config.state`) set to `on` (or `transfer`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_dns_managed_zone`
- **Check type:** resource

## Why it matters
DNS responses are not authenticated by default: a network-level attacker (on-path, via cache poisoning, or via a compromised resolver) can forge answers for your zone, redirecting users to malicious IPs, intercepting mail (MX spoofing), or defeating domain-validated TLS issuance workflows that rely on DNS. DNSSEC adds cryptographic signatures to zone records so validating resolvers can detect and reject tampered or spoofed responses. Leaving DNSSEC off on a public zone means anyone downstream who validates DNSSEC gets no protection, and your zone remains vulnerable to classic cache-poisoning and off-path spoofing attacks.

## How Checkov evaluates this
- If the zone's `visibility` is `private`, the check returns `UNKNOWN` (skipped) — DNSSEC cannot be configured on private zones, so the check is not applicable.
- Otherwise (default/public visibility), it inspects `dnssec_config[0].state`:
  - **PASS** — `state` is `on` or `transfer`.
  - **FAIL** — `state` is `off` (the default if `dnssec_config` is omitted) or any other value.

## Non-compliant example
```hcl
resource "google_dns_managed_zone" "public_zone" {
  name     = "example-public-zone"
  dns_name = "example.com."

  # No dnssec_config block -> defaults to state = "off" -> FAILS
}
```

## Remediated example
```hcl
resource "google_dns_managed_zone" "public_zone" {
  name     = "example-public-zone"
  dns_name = "example.com."

  dnssec_config {
    state         = "on"
    non_existence = "nsec3"
  }
}
```

## Remediation steps
1. Add a `dnssec_config` block to every public (non-`private`) `google_dns_managed_zone`, setting `state = "on"`.
2. After apply, retrieve the generated DS (Delegation Signer) record via `gcloud dns dns-keys list --zone=<zone>` and publish it with your domain registrar — DNSSEC is not effective end-to-end until the parent zone's registrar has the DS record.
3. Consider `non_existence = "nsec3"` if you want to avoid zone-walking (enumeration of all records) via NSEC.
4. Roll out on a non-critical zone first and monitor resolution — a botched DS record at the registrar can make the entire domain unresolvable for validating resolvers ("DNSSEC lame delegation").
5. Private zones (`visibility = "private"`) do not need this and are correctly skipped by the check.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudDNSSECEnabled.py
- GCP docs: https://cloud.google.com/dns/docs/dnssec
