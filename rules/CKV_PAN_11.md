# CKV_PAN_11: Ensure IPsec profiles do not specify use of insecure encryption algorithms
## Severity
**HIGH** (score: 7.5/10)

Allowing DES/3DES or 128/192/256-bit CBC-mode (or null) encryption in IPsec crypto profiles permits weak or absent encryption ciphers for VPN tunnels, undermining confidentiality of traffic traversing the tunnel to known cryptographic attacks.

## Summary
This check ensures PAN-OS IPsec crypto profiles do not use weak or deprecated encryption algorithms (DES, 3DES, AES-CBC variants, or "null"/no encryption) for IPsec tunnel encryption.

## Applicability
**Checkov framework(s):** `terraform`

Terraform resources `panos_ipsec_crypto_profile` and `panos_panorama_ipsec_crypto_profile`.

## Why it matters
An IPsec crypto profile defines the encryption (and authentication) algorithms permitted for Phase 2 (ESP) negotiation of an IPsec VPN tunnel. The strength of these algorithms directly determines how resistant tunnel traffic is to decryption by an attacker who can capture the encrypted packets:

- **DES** (56-bit key) is trivially breakable with modern compute (brute-forced in hours), and has been considered cryptographically broken for VPN use for decades.
- **3DES** (Triple DES) is deprecated by NIST (disallowed after 2023) due to its 64-bit block size, which is vulnerable to birthday-bound "Sweet32" collision attacks on long-lived, high-volume connections such as VPN tunnels.
- **AES-CBC modes** (`aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc`) lack built-in authenticated encryption; while paired with a separate authentication algorithm they can be made secure, CBC mode is also historically associated with padding-oracle-style vulnerabilities and is considered inferior to AEAD modes like AES-GCM, which combine confidentiality and integrity in one efficient operation and are immune to this class of attack.
- **`null`** (specified as the literal string, meaning "no encryption") transmits IPsec payload data in clear text over what is nominally a "secure" tunnel — a critical misconfiguration that defeats the entire purpose of the VPN.

Any of these algorithms in an IPsec crypto profile weakens confidentiality guarantees for all traffic traversing tunnels that reference the profile — potentially including sensitive site-to-site or remote-access VPN traffic between trusted networks.

## How Checkov evaluates this
The check (`NetworkIPsecAlgorithms`, a `BaseResourceCheck`) inspects the `encryptions` attribute (a list, since multiple algorithms can be enabled) of `panos_ipsec_crypto_profile`/`panos_panorama_ipsec_crypto_profile` resources:

- If `encryptions` is not defined at all, **FAIL** (the attribute is mandatory for the resource to be valid at Terraform plan time, so its absence is treated as a failure).
- Otherwise, iterate over every algorithm listed in `encryptions`. **FAIL** if any entry is one of: `des`, `3des`, `aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc`, or the literal string `"null"`.
- **PASS** only if every algorithm listed avoids all of the above (e.g. `aes-128-gcm`, `aes-256-gcm`).

## Non-compliant example
```hcl
resource "panos_ipsec_crypto_profile" "vpn_profile" {
  name        = "site-to-site-ipsec"
  dh_group    = "group14"
  lifetime_type   = "hours"
  lifetime_value  = 1
  authentications = ["sha256"]
  encryptions     = ["aes-128-cbc", "3des"]   # weak/deprecated encryption algorithms
}
```

## Remediated example
```hcl
resource "panos_ipsec_crypto_profile" "vpn_profile" {
  name        = "site-to-site-ipsec"
  dh_group    = "group14"
  lifetime_type   = "hours"
  lifetime_value  = 1
  authentications = ["sha256"]
  encryptions     = ["aes-256-gcm"]   # strong AEAD algorithm, no separate insecure entries
}
```

## Remediation steps
1. Replace any `des`, `3des`, `aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc`, or `null` entries in the `encryptions` list with a modern AEAD cipher such as `aes-128-gcm` or `aes-256-gcm`.
2. Confirm the peer device/VPN gateway supports the chosen algorithm — updating the crypto profile is a change that must be coordinated with the remote tunnel endpoint or the tunnel will fail to renegotiate (Phase 2 mismatch).
3. Plan for a maintenance window since changing IPsec crypto profiles used by active tunnels can cause a brief tunnel renegotiation/outage.
4. Also review the companion authentication algorithms (see CKV_PAN_12) and protocol setting (see CKV_PAN_13) on the same profile, since encryption strength alone doesn't guarantee overall tunnel security.
5. Where compliance requires FIPS-validated algorithms, restrict `encryptions` to the specific FIPS-approved GCM variants your organization has validated.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/NetworkIPsecAlgorithms.py
- PAN-OS Terraform provider `panos_ipsec_crypto_profile` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/ipsec_crypto_profile
