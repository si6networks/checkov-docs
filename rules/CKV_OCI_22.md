# CKV_OCI_22: Ensure no security groups rules allow ingress from 0.0.0.0/0 to port 22

## Severity
**CRITICAL** (score: 9.1/10)

Security group rules allowing ingress from 0.0.0.0/0 to port 22 expose SSH management access to the entire internet, a well-known high-value target for automated attacks and credential brute-forcing.

## Summary
This check ensures that no OCI Network Security Group rule (`oci_core_network_security_group_security_rule`) permits SSH (port 22) ingress from the entire internet (`0.0.0.0/0`).

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_network_security_group_security_rule`

## Why it matters
SSH is the default remote-administration protocol for Linux hosts and one of the most persistently scanned ports on the public internet. An NSG rule that allows ingress from `0.0.0.0/0` to port 22 exposes every instance attached to that NSG to unauthenticated brute-force attempts, credential-stuffing, and exploitation of any unpatched SSH-related vulnerability, from any host worldwide. Because NSGs in OCI are typically the more precise, workload-scoped alternative to broader subnet-level security lists, an overly permissive NSG rule often means an application team has directly attached an instance to public SSH exposure without the layered protection a security list might otherwise provide — making this a particularly direct and high-impact misconfiguration.

## How Checkov evaluates this
This check is built on the shared `AbsSecurityGroupUnrestrictedIngress` base class, parameterized with `port=22`. It inspects the rule's `direction`, `source`, `protocol`, and `tcp_options`:
- If `direction != "INGRESS"`, the rule is not evaluated (UNKNOWN).
- If `source != "0.0.0.0/0"`, the rule PASSES.
- Otherwise, it FAILS if either: `tcp_options` is absent and the protocol is `"all"` or `"6"` (TCP) — meaning all TCP ports, including 22, are open — or `tcp_options` is present and its `destination_port_range` (min/max) includes port 22.
- It PASSES if the TCP port range is present and explicitly excludes port 22.

## Non-compliant example
```hcl
resource "oci_core_network_security_group_security_rule" "app_ingress" {
  network_security_group_id = oci_core_network_security_group.app_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}
```

## Remediated example
```hcl
resource "oci_core_network_security_group_security_rule" "app_ingress" {
  network_security_group_id = oci_core_network_security_group.app_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "10.20.0.0/24"  # scoped to bastion/VPN subnet only
  source_type               = "CIDR_BLOCK"

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}
```

## Remediation steps
1. Remove or narrow any NSG ingress rule with `source = "0.0.0.0/0"` covering port 22 or all protocols/TCP with no port restriction.
2. Scope `source` to a bastion host CIDR, corporate VPN range, or another NSG (using `source_type = "NETWORK_SECURITY_GROUP"`) representing an approved jump host.
3. Prefer the OCI Bastion service for session-based, audited, time-limited SSH access over always-on public exposure.
4. Review both NSG rules and any parent subnet security lists together, since both layers of network control apply simultaneously in OCI.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/AbsSecurityGroupUnrestrictedIngress.py)
