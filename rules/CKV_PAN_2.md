# CKV_PAN_2: Ensure plain-text management HTTP is not enabled for an Interface Management Profile
## Severity
**MEDIUM** (score: 5.0/10)

Enabling plain-text HTTP on an Interface Management Profile allows firewall administrative sessions and credentials to be transmitted unencrypted, letting a network-positioned attacker intercept management traffic or session tokens.

## Summary
This check ensures that PAN-OS Interface Management Profiles do not enable plain-text HTTP for management access, since HTTP transmits authentication credentials and session data unencrypted.

## Applicability
**Checkov framework(s):** `ansible`, `terraform`

Terraform resource `panos_management_profile`, and Ansible task `tasks.paloaltonetworks.panos.panos_management_profile` (implemented both as a Python resource check for Terraform and as a graph-based JSON policy for Ansible).

## Why it matters
An Interface Management Profile on a PAN-OS device controls which services (HTTP, HTTPS, SSH, Telnet, ping, etc.) are permitted to reach the device's management plane through a given interface. Enabling plain-text `http` for management access means:

- Login credentials and session cookies for the firewall's web UI/API are transmitted unencrypted, making them trivially interceptable by anyone able to observe traffic on the path (on-path attacker, compromised switch, ARP spoofing on the local segment, etc.).
- Since PAN-OS devices are themselves the security enforcement point in the network, a captured management credential gives an attacker the ability to reconfigure firewall policy, disable logging, or open network paths — a compromise here undermines every other control the firewall enforces.
- HTTP has no mechanism to authenticate the server end either, exposing the management session to interception/manipulation (MITM) even absent credential theft.

Best practice is to expose only HTTPS (and SSH, if needed) on management-plane interfaces and to disable HTTP and Telnet entirely.

## How Checkov evaluates this
**Terraform** (`InterfaceMgmtProfileNoHTTP`, a `BaseResourceNegativeValueCheck`): inspects the `http` attribute of `panos_management_profile` resources.
- **FAIL** if `http` is set to `true`.
- **PASS** if `http` is absent or set to `false`.

**Ansible** (graph-based JSON policy `PanosInterfaceMgmtProfileNoHTTP.json`): evaluates `tasks.paloaltonetworks.panos.panos_management_profile` tasks with an `or` condition —
- **PASS** if the `http` attribute does not exist, OR if `http` exists but is not equal to `true`.
- **FAIL** only when `http` is explicitly present and equal to `true`.

## Non-compliant example
```hcl
resource "panos_management_profile" "mgmt" {
  name  = "allow-mgmt"
  http  = true    # plain-text HTTP management enabled
  https = true
  ssh   = true
}
```

```yaml
# Ansible
- name: Configure management profile
  paloaltonetworks.panos.panos_management_profile:
    name: allow-mgmt
    http: true       # plain-text HTTP management enabled
    https: true
    ssh: true
```

## Remediated example
```hcl
resource "panos_management_profile" "mgmt" {
  name  = "allow-mgmt"
  http  = false   # plain-text HTTP disabled
  https = true
  ssh   = true
}
```

```yaml
# Ansible
- name: Configure management profile
  paloaltonetworks.panos.panos_management_profile:
    name: allow-mgmt
    http: false      # plain-text HTTP disabled
    https: true
    ssh: true
```

## Remediation steps
1. Set `http = false` (or omit `http` entirely) on every `panos_management_profile` resource/task.
2. Ensure `https` is enabled instead, using a valid TLS certificate, for any interface that needs web-UI/API management access.
3. Review which interfaces actually reference this management profile and confirm none rely on HTTP for legitimate automation — update any HTTP-based API integrations to use HTTPS.
4. Combine with restricting the profile's permitted source IP list to only trusted management subnets, in addition to disabling HTTP.
5. Apply the same review to Telnet (see CKV_PAN_3) since both are commonly disabled together.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/InterfaceMgmtProfileNoHTTP.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosInterfaceMgmtProfileNoHTTP.json
- PAN-OS Terraform provider `panos_management_profile` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/management_profile
