# CKV2_OCI_2: Ensure NSG does not allow all traffic on RDP port (3389)

## Severity
**CRITICAL** (score: 9.5/10)

Allowing unrestricted RDP (3389) ingress from 0.0.0.0/0 exposes a remote administrative interface to the entire internet, a classic direct path to brute-force compromise or exploitation of RDP vulnerabilities.

## Summary
This check ensures OCI Network Security Group (NSG) security rules do not allow unrestricted ingress (`source = 0.0.0.0/0`) to TCP/UDP port 3389 (RDP), which would expose Windows Remote Desktop to the entire internet.

## Applicability
Terraform. Applies to the `oci_core_network_security_group_security_rule` resource.

## Why it matters
RDP (port 3389) is one of the most commonly targeted services for internet-wide scanning, brute-force credential attacks, and exploitation of RDP-specific vulnerabilities (e.g. BlueKeep/CVE-2019-0708 and various RDP protocol implementation flaws). Exposing RDP to `0.0.0.0/0` means any host on the internet can attempt authentication or exploit unpatched vulnerabilities directly against a Windows instance, without needing to first breach any other network boundary. This is a top-tier attack vector for ransomware operators, who frequently gain initial access to enterprise networks via exposed RDP. NSG rules should restrict RDP access to specific known IP ranges (corporate VPN, bastion host) or route it through a jump box / OCI Bastion service rather than exposing it directly.

## How Checkov evaluates this
Graph-based JSON policy (`OCI_NSGNotAllowRDP.json`). It passes (no failure) if any of these hold for a given rule:
1. It is not an `INGRESS` direction rule with `source = 0.0.0.0/0` and protocol other than `all` and either `tcp_options`/`udp_options` present or protocol not equal to `1` (ICMP) — i.e., non-matching rule shapes are skipped.
2. The rule's `tcp_options.destination_port_range` does not include 3389 (checked via `min`/`max` not equal to and not spanning 3389).
3. The rule's `udp_options.destination_port_range` does not include 3389 similarly.
It fails specifically when an INGRESS rule from `0.0.0.0/0` (not restricted to ICMP-only, i.e. covering TCP/UDP or "all" protocol) has a TCP or UDP destination port range that includes port 3389.

## Non-compliant example
```hcl
resource "oci_core_network_security_group" "app_nsg" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-nsg"
}

resource "oci_core_network_security_group_security_rule" "rdp_open" {
  network_security_group_id = oci_core_network_security_group.app_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6"   # TCP
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 3389
      max = 3389
    }
  }
}
```

## Remediated example
```hcl
resource "oci_core_network_security_group" "app_nsg" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-nsg"
}

resource "oci_core_network_security_group_security_rule" "rdp_restricted" {
  network_security_group_id = oci_core_network_security_group.app_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6"   # TCP
  source                    = "203.0.113.0/24"   # restricted to known corporate/VPN CIDR
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 3389
      max = 3389
    }
  }
}
```

## Remediation steps
1. Find NSG security rules with `direction = "INGRESS"`, `source = "0.0.0.0/0"`, and a TCP/UDP port range covering 3389.
2. Replace the `source` CIDR with a narrow, specific range (corporate office IPs, VPN gateway CIDR, or a bastion host's IP).
3. Prefer eliminating direct RDP ingress entirely — use the OCI Bastion service, a VPN, or a jump host that requires its own authentication before reaching RDP.
4. If broad access is genuinely required temporarily, use time-bound/just-in-time NSG rule additions rather than persistent open rules.
5. Apply the same restriction pattern to Security Lists if used instead of/alongside NSGs, since both can independently allow the traffic.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/oci/OCI_NSGNotAllowRDP.json
