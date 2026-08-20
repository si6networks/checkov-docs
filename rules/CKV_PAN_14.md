# CKV_PAN_14: Ensure a Zone Protection Profile is defined within Security Zones
## Severity
**LOW** (score: 2.0/10)

A Security Zone without an attached Zone Protection Profile lacks the firewall's flood/reconnaissance/packet-based-attack mitigations for that zone, increasing susceptibility to denial-of-service and scanning activity though not itself a direct data-exposure flaw.

## Summary
This check ensures every PAN-OS Security Zone has a non-empty Zone Protection Profile assigned, so that flood, reconnaissance, and packet-based attack protections are actively enforced on that zone.

## Applicability
**Checkov framework(s):** `ansible`, `terraform`

Terraform resources `panos_zone`, `panos_zone_entry`, and `panos_panorama_zone`, and Ansible task `tasks.paloaltonetworks.panos.panos_zone` (Python resource check for Terraform, graph-based JSON policy for Ansible).

## Why it matters
A Zone Protection Profile on PAN-OS enforces protections against network-layer attacks that target a zone as a whole, independent of any specific security policy rule — for example: SYN flood protection, ICMP/UDP/other flood protection, reconnaissance protection (port scans, host sweeps), and packet-based attack protection (malformed packet checks, IP spoofing checks). These protections operate at the zone ingress level, before traffic is even matched against security policy rules.

Leaving a security zone without a Zone Protection Profile means:

- The zone has no flood protection, leaving it exposed to volumetric denial-of-service attacks (SYN floods, UDP floods) that can exhaust firewall session tables or degrade service for legitimate traffic, even if the security policy itself is otherwise well-configured.
- Reconnaissance activity (port scans, host sweeps) against hosts in that zone goes undetected and unthrottled by the firewall, giving attackers an easier path to map the internal network before attempting exploitation.
- Malformed or spoofed packets that a Zone Protection Profile would otherwise drop at the network layer are instead passed through to be evaluated by security policy, increasing load and potentially reaching vulnerable services.

Since these protections apply regardless of what any individual security rule allows or denies, omitting a Zone Protection Profile is a gap that isn't compensated for by having tight security policy rules elsewhere.

## How Checkov evaluates this
**Terraform** (`ZoneProtectionProfile`, a `BaseResourceCheck`): inspects the `zone_profile` attribute.
- **FAIL** if `zone_profile` is absent.
- **FAIL** if `zone_profile` is present but is an empty (or whitespace-only) string.
- **PASS** only if `zone_profile` is present and set to a non-empty profile name.

**Ansible** (graph-based JSON policy `PanosZoneProtectionProfile.json`): an `and` of two conditions on `tasks.paloaltonetworks.panos.panos_zone` tasks —
- **PASS** requires `zone_profile` to exist AND to be non-empty.
- **FAIL** otherwise.

## Non-compliant example
```hcl
resource "panos_zone" "untrust" {
  name = "untrust"
  mode = "layer3"
  # zone_profile intentionally omitted -- no flood/recon protection applied
}
```

```yaml
# Ansible
- name: Configure security zone
  paloaltonetworks.panos.panos_zone:
    zone_name: untrust
    mode: layer3
    # zone_profile omitted
```

## Remediated example
```hcl
resource "panos_zone_protection_profile" "untrust_protection" {
  name                        = "untrust-zp"
  flood {
    syn { enable = true }
    icmp { enable = true }
    udp { enable = true }
  }
  scan {
    tcp_port_scan { enable = true }
  }
}

resource "panos_zone" "untrust" {
  name         = "untrust"
  mode         = "layer3"
  zone_profile = panos_zone_protection_profile.untrust_protection.name   # protection profile assigned
}
```

```yaml
# Ansible
- name: Configure security zone
  paloaltonetworks.panos.panos_zone:
    zone_name: untrust
    mode: layer3
    zone_profile: untrust-zp   # protection profile assigned
```

## Remediation steps
1. Create a Zone Protection Profile appropriate to the zone's exposure level (e.g., enable flood protection and reconnaissance protection at minimum for zones facing the internet or other untrusted networks).
2. Reference the profile via `zone_profile` on every `panos_zone`/`panos_zone_entry`/`panos_panorama_zone` resource, starting with untrust/DMZ-facing zones as the highest priority.
3. Tune flood thresholds (SYN/UDP/ICMP rate limits) based on expected legitimate traffic volume for the zone to avoid false positives dropping legitimate traffic.
4. Apply Zone Protection Profiles to internal/trust zones as well where feasible, since insider threats and lateral movement can also generate scan/flood-like traffic patterns.
5. Periodically review Zone Protection Profile logs/alerts to confirm thresholds remain appropriate as traffic patterns evolve.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/ZoneProtectionProfile.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosZoneProtectionProfile.json
- PAN-OS Terraform provider `panos_zone` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/zone
