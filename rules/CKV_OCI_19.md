# CKV_OCI_19: Ensure no security list allow ingress from 0.0.0.0:0 to port 22

## Severity
**CRITICAL** (score: 9.1/10)

Unrestricted ingress from 0.0.0.0/0 to SSH (port 22) exposes a privileged remote administrative interface to the entire internet, a classic and heavily exploited attack vector for unauthorized host access.

## Summary
This check ensures that no OCI VCN security list (`oci_core_security_list`) contains an ingress rule that opens SSH (port 22) to the entire internet (`0.0.0.0/0`).

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_security_list`

## Why it matters
SSH (TCP/22) is the primary remote-administration protocol for Linux instances and is one of the most heavily and continuously scanned ports on the internet. A security list rule that permits ingress from `0.0.0.0/0` to port 22 exposes every instance in the associated subnet to unauthenticated brute-force login attempts, credential-stuffing, and exploitation of any unpatched SSH-adjacent vulnerabilities, directly from any host on the internet. Because SSH access typically grants full shell-level control of the instance, this is one of the highest-impact misconfigurations possible in network security — a single weak or reused key/password, or an unpatched CVE, can lead to full compromise. The check is instantiated with `is_exposed_by_default=True`, meaning a security list with no explicit port restriction on an "allow-all-protocols" rule from `0.0.0.0/0` is treated as exposing port 22 by default (since an "all protocols" rule implicitly includes TCP/22).

## How Checkov evaluates this
This check subclasses the shared `AbsSecurityListUnrestrictedIngress` base logic, parameterized with `port=22` and `is_exposed_by_default=True`. For each ingress rule in the security list it inspects `source` and `protocol` (and `tcp_options` if protocol is TCP). It FAILS when:
- The rule's `source` is `0.0.0.0/0`, AND
- The protocol is "all" (or unrestricted) — which by default is treated as exposing port 22 — or the protocol is TCP (`6`) and the rule's `tcp_options` port range includes port 22 (or no port range is specified, meaning all TCP ports, including 22, are open).

It PASSES if the source is scoped to something other than `0.0.0.0/0`, or if TCP options exist and specifically exclude port 22 from the allowed range.

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
      min = 22
      max = 22
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
      min = 22
      max = 22
    }
  }
}
```

## Remediation steps
1. Remove any ingress rule that permits port 22 (or "all protocols") from `source = "0.0.0.0/0"`.
2. Scope the `source` CIDR to a bastion host subnet, a corporate VPN range, or an OCI Bastion service endpoint.
3. Prefer OCI's fully managed Bastion service (session-based, short-lived, audited access) over direct public SSH exposure entirely.
4. If broad SSH access is genuinely required temporarily, use time-boxed, audited exceptions rather than a permanent open rule, and enforce key-based auth with password authentication disabled on the instance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/SecurityListUnrestrictedIngress22.py)
