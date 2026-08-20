# CKV_ALI_33: Alibaba Cloud Cypher Policy are secure
## Severity
**LOW** (score: 2.0/10)

Allowing TLS 1.0/1.1 on the load balancer permits use of protocol versions with known cryptographic weaknesses, enabling downgrade and man-in-the-middle attacks against traffic in transit.

## Summary
This check ensures that an Alibaba Cloud SLB (Server Load Balancer) TLS cipher policy does not permit the deprecated and insecure TLS 1.0 or TLS 1.1 protocol versions.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_slb_tls_cipher_policy`

## Why it matters
TLS 1.0 and TLS 1.1 have well-documented cryptographic weaknesses (e.g., susceptibility to BEAST, POODLE-adjacent padding oracle issues, and reliance on weak MAC/cipher constructions such as RC4 and CBC mode combinations) and are formally deprecated by the IETF (RFC 8996) and by major browsers and payment-card industry standards (PCI-DSS 4.0 disallows them for cardholder data environments). Allowing these protocol versions on a load balancer's cipher policy exposes clients and the service to downgrade attacks, where an on-path attacker forces negotiation to the weaker protocol version and subsequently exploits its known cryptographic flaws to decrypt or tamper with traffic. Since the SLB cipher policy applies to every listener that references it, a single misconfigured policy can weaken TLS posture across an entire fleet of public-facing services.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck`, which fails if the inspected attribute contains any of a defined set of "forbidden" values.
- **Inspected key:** `tls_versions`
- **Forbidden values:** `"TLSv1.1"` and `"TLSv1.0"`
- **FAIL** if `tls_versions` includes `"TLSv1.0"` and/or `"TLSv1.1"`.
- **PASS** if `tls_versions` only contains modern protocol versions (e.g., `"TLSv1.2"`, `"TLSv1.3"`) or the forbidden values are absent.

## Non-compliant example
```hcl
resource "alicloud_slb_tls_cipher_policy" "example" {
  name         = "example-policy"
  tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2"]
  ciphers      = ["ECDHE-RSA-AES128-SHA256"]
}
```

## Remediated example
```hcl
resource "alicloud_slb_tls_cipher_policy" "example" {
  name         = "example-policy"
  tls_versions = ["TLSv1.2", "TLSv1.3"]  # <-- removed TLSv1.0 and TLSv1.1
  ciphers      = ["ECDHE-RSA-AES128-SHA256"]
}
```

## Remediation steps
1. Edit the `tls_versions` list on the `alicloud_slb_tls_cipher_policy` resource to remove `"TLSv1.0"` and `"TLSv1.1"`.
2. Retain only `"TLSv1.2"` and, where client compatibility allows, `"TLSv1.3"`.
3. Confirm downstream/legacy clients (older mobile apps, IoT devices, internal services) support TLS 1.2+ before rollout, since this change can break connectivity for clients that only speak the deprecated protocols.
4. Re-associate/verify the cipher policy is attached to the intended SLB HTTPS listeners after the change.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/TLSPoliciesAreSecure.py)
