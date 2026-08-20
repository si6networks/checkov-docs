# CKV_OPENSTACK_5: Ensure firewall rule set a destination IP
## Severity
**LOW** (score: 2.0/10)

A firewall rule left without a specific destination_ip_address (or set to 0.0.0.0/0) applies to any destination host, weakening network segmentation and widening the blast radius of the rule, though it is an authorization-scoping gap rather than a direct exposure of a specific exploitable service.

## Summary
This check ensures OpenStack FWaaS (Firewall-as-a-Service v1) rules explicitly define a `destination_ip_address`, and that it is not set to an unrestricted `0.0.0.0/0` (or bare `0.0.0.0`), so that firewall rules don't implicitly or explicitly permit traffic to any destination.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource type `openstack_fw_rule_v1` (OpenStack Networking FWaaS v1 firewall rule).

## Why it matters
An OpenStack firewall rule (`openstack_fw_rule_v1`) without a defined destination IP, or with a destination of `0.0.0.0/0`, effectively allows matching traffic (typically permit rules, given the source/destination/protocol/port matching model) to reach any host in the protected network topology. This defeats the purpose of a stateful/stateless firewall rule set which is meant to enforce least-privilege network segmentation:

- Overly broad destination scoping means a rule intended to authorize access to one specific service (e.g., a database host) instead opens a path to the entire address space behind the firewall.
- It increases blast radius if the rule is ever misapplied to an unintended firewall policy/router, since there's no destination constraint limiting where the traffic can land.
- It undermines network segmentation strategies (e.g., isolating a DMZ tier from a data tier) since a rule with no destination restriction can traverse segment boundaries that other controls assume are enforced at the firewall layer.

Explicitly scoping `destination_ip_address` to the intended host/subnet is a core input to defense-in-depth network design; omitting it (or defaulting to "any") silently broadens every rule's effect.

## How Checkov evaluates this
The check (`FirewallRuleSetDestinationIP`, a `BaseResourceNegativeValueCheck`) inspects the `destination_ip_address` attribute of `openstack_fw_rule_v1` resources:

- **FAIL** if `destination_ip_address` is missing entirely (`missing_attribute_result=CheckResult.FAILED` — unlike many negative-value checks, an absent attribute is treated as non-compliant here, not compliant).
- **FAIL** if `destination_ip_address` is explicitly set to `"0.0.0.0/0"` or `"0.0.0.0"` (the forbidden values).
- **PASS** only when `destination_ip_address` is present and set to a specific, non-"any" IP address or CIDR.

## Non-compliant example
```hcl
resource "openstack_fw_rule_v1" "allow_web" {
  name                   = "allow-web-egress"
  action                 = "allow"
  protocol               = "tcp"
  destination_port       = "443"
  destination_ip_address = "0.0.0.0/0"   # unrestricted destination
  enabled                = true
}
```

## Remediated example
```hcl
resource "openstack_fw_rule_v1" "allow_web" {
  name                   = "allow-web-egress"
  action                 = "allow"
  protocol               = "tcp"
  destination_port       = "443"
  destination_ip_address = "203.0.113.10/32"   # scoped to the intended destination host
  enabled                = true
}
```

## Remediation steps
1. Identify every `openstack_fw_rule_v1` resource missing `destination_ip_address` or set to `0.0.0.0/0`/`0.0.0.0`.
2. Determine the actual intended destination(s) for each rule and set `destination_ip_address` to the narrowest CIDR/IP that covers them.
3. If a rule genuinely needs to match multiple destinations, create one explicit rule per destination range rather than defaulting to "any," to preserve auditability of what each rule actually authorizes.
4. Review the firewall policy (`openstack_fw_policy_v1`) that references this rule to confirm rule ordering still enforces the intended default-deny posture.
5. Re-validate connectivity after tightening, since previously "any"-scoped rules may have been masking a missing more-specific rule.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/openstack/FirewallRuleSetDestinationIP.py
- Terraform OpenStack `openstack_fw_rule_v1` reference: https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/fw_rule_v1
