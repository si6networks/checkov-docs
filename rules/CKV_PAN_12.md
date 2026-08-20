# CKV_PAN_12: Ensure IPsec profiles do not specify use of insecure authentication algorithms
## Severity
**MEDIUM** (score: 5.0/10)

Permitting none/md5/sha1 as IPsec authentication algorithms allows cryptographically weak or absent integrity protection on VPN tunnels, enabling tampering or spoofing of tunneled traffic via known collision/preimage weaknesses.

## Summary
This check ensures PAN-OS IPsec crypto profiles do not use weak or deprecated authentication/integrity algorithms (`none`, MD5, or SHA-1) for IPsec ESP authentication.

## Applicability
**Checkov framework(s):** `ansible`, `terraform`

Terraform resources `panos_ipsec_crypto_profile` and `panos_panorama_ipsec_crypto_profile`, and Ansible task `tasks.paloaltonetworks.panos.panos_ipsec_profile` (Python resource check for Terraform, graph-based JSON policy for Ansible).

## Why it matters
The authentication algorithm in an IPsec crypto profile provides integrity and authenticity verification for ESP payloads — it's what prevents an attacker from tampering with or forging tunnel packets even if they can't decrypt them. Weak choices here undermine that guarantee:

- **`none`** disables integrity/authentication protection on the ESP payload entirely (relying only on encryption, if any, for protection), leaving the tunnel vulnerable to active tampering attacks such as bit-flipping or packet injection that the encryption algorithm alone may not detect.
- **MD5** has known collision vulnerabilities and is considered cryptographically broken; using HMAC-MD5 for packet authentication provides materially weaker forgery resistance than modern alternatives.
- **SHA-1** is deprecated by NIST for many security use cases due to demonstrated collision attacks (e.g., the SHAttered attack), and continued use in HMAC constructions is discouraged in favor of SHA-256 or stronger.

Since IPsec authentication is what an attacker must defeat to inject or modify traffic inside the tunnel undetected, weak algorithms here materially lower the cost of a successful active man-in-the-middle or replay/tampering attack against VPN traffic.

## How Checkov evaluates this
**Terraform** (`NetworkIPsecAuthAlgorithms`, a `BaseResourceCheck`): inspects the `authentications` attribute (a list) of `panos_ipsec_crypto_profile`/`panos_panorama_ipsec_crypto_profile` resources.
- If `authentications` is not defined at all, **FAIL** (mandatory attribute; absence is invalid config, treated as fail).
- Otherwise, iterate over every algorithm. **FAIL** if any entry is `none`, `md5`, or `sha1`.
- **PASS** if every listed algorithm avoids all three (e.g. `sha256`, `sha384`, `sha512`).

**Ansible** (graph-based JSON policy `PanosIPsecAuthenticationAlgorithms.json`): evaluates `tasks.paloaltonetworks.panos.panos_ipsec_profile` tasks with an `and` of four conditions —
- **PASS** requires `esp_authentication` to exist AND not contain `"none"` AND not contain `"md5"` AND not contain `"sha1"`.
- **FAIL** if `esp_authentication` is missing, or contains any of those insecure values.

## Non-compliant example
```hcl
resource "panos_ipsec_crypto_profile" "vpn_profile" {
  name            = "site-to-site-ipsec"
  dh_group        = "group14"
  lifetime_type   = "hours"
  lifetime_value  = 1
  authentications = ["sha1"]        # weak authentication algorithm
  encryptions     = ["aes-256-gcm"]
}
```

```yaml
# Ansible
- name: Configure IPsec profile
  paloaltonetworks.panos.panos_ipsec_profile:
    name: site-to-site-ipsec
    esp_encryption: [aes-256-gcm]
    esp_authentication: [sha1]      # weak authentication algorithm
```

## Remediated example
```hcl
resource "panos_ipsec_crypto_profile" "vpn_profile" {
  name            = "site-to-site-ipsec"
  dh_group        = "group14"
  lifetime_type   = "hours"
  lifetime_value  = 1
  authentications = ["sha256"]      # strong authentication algorithm
  encryptions     = ["aes-256-gcm"]
}
```

```yaml
# Ansible
- name: Configure IPsec profile
  paloaltonetworks.panos.panos_ipsec_profile:
    name: site-to-site-ipsec
    esp_encryption: [aes-256-gcm]
    esp_authentication: [sha256]    # strong authentication algorithm
```

## Remediation steps
1. Replace any `none`, `md5`, or `sha1` entries in `authentications`/`esp_authentication` with `sha256` or a stronger option (`sha384`, `sha512`) supported by both endpoints.
2. Coordinate the change with the remote VPN peer — a Phase 2 authentication algorithm mismatch will prevent tunnel renegotiation, causing an outage if not planned.
3. Note that when using AES-GCM encryption (an AEAD cipher), the ESP authentication field may be handled differently — confirm your PAN-OS version's requirements for combining GCM encryption with a separate authentication algorithm.
4. Review the companion encryption algorithm setting (CKV_PAN_11) and protocol setting (CKV_PAN_13) together, since all three combine to determine overall tunnel cryptographic strength.
5. Schedule the update for a maintenance window given the tunnel renegotiation impact.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/NetworkIPsecAuthAlgorithms.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosIPsecAuthenticationAlgorithms.json
- PAN-OS Terraform provider `panos_ipsec_crypto_profile` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/ipsec_crypto_profile
