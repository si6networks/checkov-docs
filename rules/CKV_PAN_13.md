# CKV_PAN_13: Ensure IPsec profiles do not specify use of insecure protocols
## Severity
**MEDIUM** (score: 5.0/10)

Configuring the IPsec profile to use the AH protocol (which provides authentication only, no encryption) instead of ESP exposes tunneled traffic content in the clear despite being configured as a VPN, defeating the confidentiality goal of the tunnel.

## Summary
This check ensures PAN-OS IPsec crypto profiles do not configure the legacy Authentication Header (AH) protocol, which provides no payload confidentiality (no encryption) for tunnel traffic.

## Applicability
**Checkov framework(s):** `ansible`, `terraform`

Terraform resources `panos_ipsec_crypto_profile` and `panos_panorama_ipsec_crypto_profile`, and Ansible task `tasks.paloaltonetworks.panos.panos_ipsec_profile` (Python resource check for Terraform, graph-based JSON policy for Ansible).

## Why it matters
IPsec offers two payload protocols: ESP (Encapsulating Security Payload), which provides both encryption and integrity/authentication, and AH (Authentication Header), which provides only integrity/authentication with **no encryption of the payload at all**. Configuring AH for an IPsec crypto profile means:

- All data transmitted over the tunnel is sent in clear text — anyone able to observe the network path (on-path attacker, compromised intermediate router, ISP-level interception) can read the full content of what is nominally a "VPN" tunnel.
- AH is largely obsolete in modern IPsec deployments precisely because it offers no confidentiality; ESP with a null-cipher option existed for similar niche cases but virtually all real-world security requirements need encrypted payload, which only ESP provides.
- AH also has known interoperability problems with NAT traversal (NAT breaks AH's integrity check since it covers IP header fields that NAT devices rewrite), so its presence is both an insecure and often non-functional configuration.

Any IPsec tunnel using AH instead of ESP is not actually providing confidentiality protection despite appearing to be a "secure" VPN configuration.

## How Checkov evaluates this
**Terraform** (`NetworkIPsecProtocols`, a `BaseResourceNegativeValueCheck`): inspects the `protocol` attribute of `panos_ipsec_crypto_profile`/`panos_panorama_ipsec_crypto_profile` resources.
- **FAIL** if `protocol` is set to `"ah"`.
- **PASS** if `protocol` is absent or set to anything other than `"ah"` (i.e., `esp`, the default and only encrypting option).

**Ansible** (graph-based JSON policy `PanosIPsecProtocols.json`): a single condition on `tasks.paloaltonetworks.panos.panos_ipsec_profile` tasks —
- **PASS** if the `ah_authentication` attribute does not exist at all (i.e., AH was never configured on the profile).
- **FAIL** if `ah_authentication` is present, implying AH protocol usage is configured.

## Non-compliant example
```hcl
resource "panos_ipsec_crypto_profile" "vpn_profile" {
  name            = "site-to-site-ipsec"
  dh_group        = "group14"
  protocol        = "ah"            # no payload encryption at all
  authentications = ["sha256"]
}
```

```yaml
# Ansible
- name: Configure IPsec profile
  paloaltonetworks.panos.panos_ipsec_profile:
    name: site-to-site-ipsec
    ah_authentication: [sha256]     # AH protocol configured, no encryption
```

## Remediated example
```hcl
resource "panos_ipsec_crypto_profile" "vpn_profile" {
  name            = "site-to-site-ipsec"
  dh_group        = "group14"
  protocol        = "esp"           # ESP provides both encryption and integrity
  authentications = ["sha256"]
  encryptions     = ["aes-256-gcm"]
}
```

```yaml
# Ansible
- name: Configure IPsec profile
  paloaltonetworks.panos.panos_ipsec_profile:
    name: site-to-site-ipsec
    esp_encryption: [aes-256-gcm]
    esp_authentication: [sha256]    # ESP instead of AH
```

## Remediation steps
1. Change `protocol` (Terraform) from `"ah"` to `"esp"`, or remove any `ah_authentication` block (Ansible) in favor of ESP-specific settings (`esp_encryption`/`esp_authentication`).
2. Choose strong ESP encryption and authentication algorithms alongside the protocol change (see CKV_PAN_11, CKV_PAN_12).
3. Coordinate with the remote VPN peer, as switching from AH to ESP is a Phase 2 negotiation change that will require the tunnel to renegotiate and may need matching configuration on the peer device.
4. If AH is present due to a legacy interoperability requirement, evaluate whether that requirement still stands — AH is rarely required by any modern peer and its removal typically only improves both security and NAT compatibility.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/NetworkIPsecProtocols.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosIPsecProtocols.json
- PAN-OS Terraform provider `panos_ipsec_crypto_profile` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/ipsec_crypto_profile
