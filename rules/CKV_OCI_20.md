# CKV_OCI_20: Ensure no security list allow ingress from 0.0.0.0:0 to port 3389

## Severity
**CRITICAL** (score: 9.0/10)

Unrestricted ingress from 0.0.0.0/0 to RDP (port 3389) exposes a privileged remote administrative interface to the public internet, enabling brute-force and exploitation of a high-value remote access service.

## Summary
This check ensures that no OCI VCN security list (`oci_core_security_list`) contains an ingress rule that opens RDP (port 3389) to the entire internet (`0.0.0.0/0`).

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `oci_core_security_list`

## Why it matters
RDP (TCP/3389) is the standard remote-desktop administration protocol for Windows instances and, like SSH, is one of the most persistently scanned and attacked ports on the internet. Exposing RDP publicly invites brute-force login attempts, credential-stuffing, and exploitation of known RDP-stack vulnerabilities (e.g., BlueKeep/CVE-2019-0708-class remote code execution flaws), any of which can lead to full compromise of the Windows host. Unlike the port-22 check, this check is instantiated with `is_exposed_by_default=False` — meaning an "allow all protocols" rule from `0.0.0.0/0` with no specific TCP port restriction is not automatically assumed to expose port 3389 (it must be explicitly matched by a TCP rule whose port range includes 3389, or an explicit 3389 rule).

## How Checkov evaluates this
This check subclasses the shared `AbsSecurityListUnrestrictedIngress` base logic, parameterized with `port=3389` and `is_exposed_by_default=False`. For each ingress rule it inspects `source` and `protocol` (and `tcp_options` when TCP). It FAILS when the rule's `source` is `0.0.0.0/0` AND the protocol is TCP (`6`) with a `tcp_options` port range that includes 3389 (or, given `is_exposed_by_default=False`, an "all protocols" rule with no port restriction is not treated as an automatic RDP-exposure match the way it is for port 22). It PASSES if the source is scoped to something other than `0.0.0.0/0`, or the TCP port range explicitly excludes 3389.

## Non-compliant example
```hcl
resource "oci_core_security_list" "app_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-security-list"

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"

    tcp_options {
      min = 3389
      max = 3389
    }
  }
}
```

## Remediated example
```hcl
resource "oci_core_security_list" "app_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-security-list"

  ingress_security_rules {
    protocol = "6"
    source   = "10.20.0.0/24"  # scoped to bastion/VPN subnet only

    tcp_options {
      min = 3389
      max = 3389
    }
  }
}
```

## Remediation steps
1. Remove any ingress rule permitting port 3389 from `source = "0.0.0.0/0"`.
2. Scope the `source` CIDR to a bastion subnet, corporate VPN range, or a jump host used specifically for RDP access.
3. Prefer a bastion/jump-host architecture, RDP Gateway, or VPN-only access rather than direct public RDP exposure.
4. Enforce Network Level Authentication (NLA) and strong account lockout policies on the Windows host as defense-in-depth, even after network exposure is remediated.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/SecurityListUnrestrictedIngress3389.py)
