# CKV_OCI_16: Ensure VCN has an inbound security list

## Severity
**MEDIUM** (score: 5.0/10)

A VCN security list with no inbound rules defined is a configuration-completeness gap rather than an active exposure, but it can mask unintended default-permissive behavior or block legitimate traffic, warranting a moderate rating.

## Summary
This check ensures that an OCI Virtual Cloud Network (VCN) security list (`oci_core_security_list`) defines at least one ingress security rule, rather than being an ingress-empty security list.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `oci_core_security_list`

## Why it matters
A security list with no ingress rules at all is a signal of an incomplete or misconfigured network security definition — either the list was never finished, or ingress rules were meant to be defined but accidentally omitted (e.g., a copy-paste error dropping the `ingress_security_rules` block). While an empty ingress list technically blocks all inbound traffic (a "deny by default" outcome), in practice such a misconfiguration usually means the intended traffic flow is broken, prompting operators to later "fix" it by attaching an overly permissive rule (e.g., allow-all) under time pressure — which is a worse security outcome. This check exists to flag security lists that appear to lack any deliberate ingress policy, prompting review of whether the list is intentionally deny-all or missing configuration.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute `ingress_security_rules[0].protocol` on `oci_core_security_list`. The check passes if this value is present with any content (`ANY_VALUE`), meaning at least one ingress rule with a protocol is defined. It fails if `ingress_security_rules` is absent or the first rule lacks a `protocol` field.

## Non-compliant example
```hcl
resource "oci_core_security_list" "app_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-security-list"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "6"
  }
  # No ingress_security_rules block defined
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
    source   = "10.0.0.0/16"

    tcp_options {
      min = 443
      max = 443
    }
  }

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "6"
  }
}
```

## Remediation steps
1. Review the intended traffic flow for the subnet/VCN this security list protects.
2. Add at least one `ingress_security_rules` block scoped to the narrowest necessary source CIDR, protocol, and port range for legitimate traffic.
3. Avoid defaulting to `0.0.0.0/0` for the source — scope to known VCN CIDRs, load balancer subnets, or bastion/VPN ranges (see CKV_OCI_19/CKV_OCI_20 for specific port-exposure checks).
4. If the list is intentionally deny-all-inbound by design, document that intent clearly so future maintainers don't misinterpret the empty list as an oversight.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/SecurityListIngress.py)
