# CKV_GCP_17: Ensure that RSASHA1 is not used for the zone-signing and key-signing keys in Cloud DNS DNSSEC
## Severity
**MEDIUM** (score: 4.5/10)

RSASHA1 is a weak signing algorithm for DNSSEC keys that is more susceptible to cryptographic attack than modern alternatives, weakening the zone's tamper-evidence guarantees without fully disabling protection.

## Summary
This check fails when a `google_dns_managed_zone`'s DNSSEC `default_key_specs` block uses the `rsasha1` algorithm for its signing keys.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_dns_managed_zone`
- **Check type:** resource

## Why it matters
RSA/SHA-1 is a deprecated, cryptographically weak signing algorithm — SHA-1 has known collision attacks and is being phased out across the industry (browsers, CAs, and DNSSEC guidance all discourage it). Using it for DNSSEC zone-signing or key-signing keys undermines the very protection DNSSEC exists to provide: if the signing algorithm is broken or considered weak, an attacker with sufficient resources could potentially forge valid-looking signed records, or the growing distrust of SHA-1 could cause future resolver-side deprecation of RSASHA1 validation entirely, silently breaking DNSSEC validation for the zone. GCP's own documentation recommends RSASHA256 (the default) instead.

## How Checkov evaluates this
The check inspects `dnssec_config[0].default_key_specs`:
- For each entry in `default_key_specs`, if `algorithm` is present and equals `["rsasha1"]`, the check **FAILS**.
- If `dnssec_config` has no `default_key_specs` at all, the check **PASSES** — GCP's implicit default algorithm is `RSASHA256`, which is acceptable.
- Otherwise (an explicit algorithm other than `rsasha1`, e.g. `rsasha256`, `ecdsap256sha256`), the check **PASSES**.

## Non-compliant example
```hcl
resource "google_dns_managed_zone" "public_zone" {
  name     = "example-public-zone"
  dns_name = "example.com."

  dnssec_config {
    state = "on"

    default_key_specs {
      algorithm  = "rsasha1"
      key_type   = "keySigning"
      key_length = 2048
    }
  }
}
```

## Remediated example
```hcl
resource "google_dns_managed_zone" "public_zone" {
  name     = "example-public-zone"
  dns_name = "example.com."

  dnssec_config {
    state = "on"

    default_key_specs {
      algorithm  = "rsasha256"
      key_type   = "keySigning"
      key_length = 2048
    }

    default_key_specs {
      algorithm  = "rsasha256"
      key_type   = "zoneSigning"
      key_length = 1024
    }
  }
}
```

## Remediation steps
1. Change every `default_key_specs.algorithm` value away from `rsasha1` to `rsasha256` (or `ecdsap256sha256` for a smaller, more modern key).
2. If you simply omit `default_key_specs` entirely, GCP applies the secure `RSASHA256` default — that also satisfies the check.
3. Changing the signing algorithm on an already-signed zone requires a **key rollover**; do this carefully to avoid a validation gap (temporarily publish both old and new DS records with your registrar per RFC 6781 double-signature rollover guidance) rather than switching abruptly.
4. Re-verify with `gcloud dns dns-keys list --zone=<zone>` after apply.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleCloudDNSKeySpecsRSASHA1.py
- GCP docs: https://cloud.google.com/dns/docs/dnssec-advanced
