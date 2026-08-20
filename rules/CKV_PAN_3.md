# CKV_PAN_3: Ensure plain-text management Telnet is not enabled for an Interface Management Profile
## Severity
**MEDIUM** (score: 5.0/10)

Enabling Telnet on an Interface Management Profile exposes an entirely unencrypted administrative protocol, letting anyone able to observe the network capture firewall admin credentials and commands in cleartext.

## Summary
This check ensures that PAN-OS Interface Management Profiles do not enable Telnet for management access, since Telnet transmits authentication credentials and session data completely unencrypted.

## Applicability
Terraform resource `panos_management_profile`, and Ansible task `tasks.paloaltonetworks.panos.panos_management_profile` (implemented both as a Python resource check for Terraform and as a graph-based JSON policy for Ansible).

## Why it matters
Telnet is a legacy remote-management protocol with no encryption and no integrity protection whatsoever. Enabling `telnet` on a PAN-OS Interface Management Profile means:

- Every keystroke of an administrative session — including the login username and password — is sent in clear text over the network, trivially capturable by packet sniffing on any segment the traffic transits.
- Unlike SSH, Telnet provides no server authentication either, making the management session fully susceptible to on-path interception and manipulation (session hijacking, credential replay).
- Because PAN-OS is the network's security enforcement point, a captured management credential lets an attacker reconfigure firewall rules, disable logging/alerting, or exfiltrate configuration — a single Telnet session compromise can undermine the entire perimeter's security posture.
- Telnet has been considered obsolete for administrative access for well over two decades; virtually every compliance framework (PCI-DSS, CIS benchmarks, NIST) explicitly calls out disabling it in favor of SSH/HTTPS.

## How Checkov evaluates this
**Terraform** (`InterfaceMgmtProfileNoTelnet`, a `BaseResourceNegativeValueCheck`): inspects the `telnet` attribute of `panos_management_profile` resources.
- **FAIL** if `telnet` is set to `true`.
- **PASS** if `telnet` is absent or set to `false`.

**Ansible** (graph-based JSON policy `PanosInterfaceMgmtProfileNoTelnet.json`): evaluates `tasks.paloaltonetworks.panos.panos_management_profile` tasks with an `or` condition —
- **PASS** if the `telnet` attribute does not exist, OR if `telnet` exists but is not equal to `true`.
- **FAIL** only when `telnet` is explicitly present and equal to `true`.

## Non-compliant example
```hcl
resource "panos_management_profile" "mgmt" {
  name   = "allow-mgmt"
  telnet = true    # plain-text Telnet management enabled
  ssh    = true
  https  = true
}
```

```yaml
# Ansible
- name: Configure management profile
  paloaltonetworks.panos.panos_management_profile:
    name: allow-mgmt
    telnet: true     # plain-text Telnet management enabled
    ssh: true
    https: true
```

## Remediated example
```hcl
resource "panos_management_profile" "mgmt" {
  name   = "allow-mgmt"
  telnet = false   # Telnet disabled
  ssh    = true
  https  = true
}
```

```yaml
# Ansible
- name: Configure management profile
  paloaltonetworks.panos.panos_management_profile:
    name: allow-mgmt
    telnet: false    # Telnet disabled
    ssh: true
    https: true
```

## Remediation steps
1. Set `telnet = false` (or omit `telnet` entirely) on every `panos_management_profile` resource/task.
2. Use SSH for CLI-based management instead, ensuring a strong host key policy and (where supported) certificate-based or key-based authentication.
3. Audit any existing automation or legacy scripts that may still rely on Telnet management access and migrate them to SSH/HTTPS APIs.
4. Restrict the management profile's permitted source IP list to trusted management subnets as an additional layer of defense.
5. Apply the same review to plain-text HTTP (see CKV_PAN_2) since both legacy protocols are typically disabled together as part of hardening.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/InterfaceMgmtProfileNoTelnet.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosInterfaceMgmtProfileNoTelnet.json
- PAN-OS Terraform provider `panos_management_profile` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/management_profile
