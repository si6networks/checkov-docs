# CKV_GCP_4: Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites

## Severity
**HIGH** (score: 7.5/10)

Allowing weak-cipher SSL policies on load balancers exposes TLS connections to downgrade and cryptographic attacks (e.g. BEAST, RC4-based attacks), directly threatening the confidentiality/integrity of in-transit traffic for internet-facing services.

## Summary
This check verifies that a `google_compute_ssl_policy` used by HTTPS/SSL proxy load balancers doesn't permit outdated TLS versions or weak ciphers such as RC4, 3DES, or CBC-mode RSA suites.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to the `google_compute_ssl_policy` resource, which is then referenced by HTTPS/SSL proxy load balancer target proxies.

## Why it matters
SSL policies control which TLS protocol versions and cipher suites a GCP load balancer will negotiate with clients. Weak or legacy cipher suites — RC4 (broken stream cipher with known biases), 3DES (small 64-bit block size vulnerable to birthday-bound attacks like SWEET32), and CBC-mode suites without proper padding protections (vulnerable to padding-oracle attacks like Lucky13/POODLE-class issues) — allow a network attacker (e.g., on-path/MITM) to potentially downgrade, weaken, or in some cases fully break the confidentiality of TLS sessions terminated at the load balancer. Modern PCI-DSS, NIST, and most compliance frameworks explicitly disallow these ciphers. Using GCP's `RESTRICTED` profile (or `MODERN` pinned to TLS 1.2+) instead of a permissive `COMPATIBLE`/custom policy that includes legacy suites ensures the load balancer only negotiates modern, strong cryptography.

## How Checkov evaluates this
The check inspects the `profile` attribute:
- **PASS** if `profile = "RESTRICTED"` (GCP's strongest built-in profile, excludes all weak ciphers and older TLS).
- **PASS** if `profile = "MODERN"` AND `min_tls_version = "TLS_1_2"`.
- **PASS** if `profile = "CUSTOM"` AND `custom_features` does NOT include any of: `TLS_RSA_WITH_AES_128_GCM_SHA256`, `TLS_RSA_WITH_AES_256_GCM_SHA384`, `TLS_RSA_WITH_AES_128_CBC_SHA`, `TLS_RSA_WITH_AES_256_CBC_SHA`, `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (these are non-PFS/legacy RSA-key-exchange suites).
- **FAIL** in all other cases, e.g. `profile = "COMPATIBLE"` (permits old ciphers/TLS 1.0 by design), `MODERN` without pinning `min_tls_version` to `TLS_1_2`, or `CUSTOM` including any of the listed weak suites.

## Non-compliant example
```hcl
resource "google_compute_ssl_policy" "lb_policy" {
  name    = "lb-ssl-policy"
  profile = "COMPATIBLE"
}
```

## Remediated example
```hcl
resource "google_compute_ssl_policy" "lb_policy" {
  name    = "lb-ssl-policy"
  profile = "RESTRICTED"
}
```

## Remediation steps
1. Change `profile` to `"RESTRICTED"` where compatible with client requirements — this is the simplest fix and excludes all legacy/weak ciphers.
2. If `MODERN` is required for broader client compatibility, also set `min_tls_version = "TLS_1_2"` explicitly.
3. If using `CUSTOM` for fine-grained control, remove any of the flagged RSA-key-exchange / CBC / 3DES cipher suites from `custom_features` and prefer ECDHE/GCM suites for forward secrecy.
4. Attach the resulting SSL policy to your `google_compute_target_https_proxy` or `google_compute_target_ssl_proxy` via the `ssl_policy` attribute.
5. Test client compatibility before rolling out `RESTRICTED` broadly — very old clients (e.g., legacy IoT devices, ancient browsers) may lose the ability to connect; check GCP's SSL policy documentation for the exact minimum TLS version/cipher set each profile allows.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeSSLPolicy.py)
- [GCP: SSL policies overview](https://cloud.google.com/load-balancing/docs/ssl-policies-concepts)
