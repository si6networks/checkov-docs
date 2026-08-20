# CKV_PAN_7: Ensure security rules do not have 'source_addresses' and 'destination_addresses' both containing values of 'any'

## Severity
**LOW** (score: 2.0/10)

A rule with both source and destination addresses set to `any` is effectively an unrestricted allow-all between zones, eliminating network segmentation and letting any compromised host reach any destination the rule's zones/services permit.

## Summary
This check fails a Palo Alto Networks (PAN-OS) security policy rule when **both** its source and destination addresses are set to `any`, since that combination effectively allows traffic between every zone/host pair the rule's zones cover.

## Applicability
- **Terraform**: resource types `panos_security_policy` and `panos_security_rule_group` (each `rule` block, attributes `source_addresses` / `destination_addresses`).
- **Ansible**: task `tasks.paloaltonetworks.panos.panos_security_rule` (attributes `source_ip` / `destination_ip`), evaluated via a Checkov graph check.

## Why it matters
A rule with `source_addresses = ["any"]` **and** `destination_addresses = ["any"]` places no constraint on which hosts can talk to which hosts within the zones the rule covers — only the zone pairing, application, and service (if restricted) limit the traffic. This is the network-address equivalent of a wildcard ACL: any single compromised host in the source zone can reach any host in the destination zone matching the rule's other criteria. It removes the ability to contain lateral movement, makes it impossible to reason about "who can reach what" from the ruleset alone, and is a common finding in compliance frameworks (PCI-DSS, NIST 800-53 access control requirements) because it violates least-privilege network segmentation. Restricting at least one side (typically the more specific, e.g. known source subnets or known destination servers) preserves the principle that a rule should describe an intentional, bounded traffic flow.

## How Checkov evaluates this
**Terraform (`PolicyNoSrcAnyDstAny.py`)**: For each `rule` block:
- If `source_addresses` is missing → FAIL.
- If `source_addresses` is present, iterate its values; when a value equals `"any"`:
  - If `destination_addresses` is missing → FAIL.
  - If `destination_addresses` is present, iterate its values; if any equals `"any"` → FAIL (source AND destination both `any`).
- If neither side is `any`, or only one side is `any`, the rule passes.
- If the resource has no `rule` blocks → result is `UNKNOWN`.

**Ansible (graph check `PanosPolicyNoSrcAnyDstAny.json`)**: Fails when *either* `source_ip` is present/non-empty/equal to `"any"` **or** `destination_ip` is present/non-empty/equal to `"any"` — i.e., the Ansible graph check flags either side being `any` individually (a stricter condition than the Terraform check, which only flags when both are `any`). Be aware of this difference when comparing findings across IaC types.

## Non-compliant example
```hcl
resource "panos_security_rule_group" "broad_allow" {
  rule {
    name                  = "allow-any-any"
    source_zones          = ["trust"]
    destination_zones     = ["dmz"]
    source_addresses      = ["any"]
    destination_addresses = ["any"]
    applications           = ["web-browsing", "ssl"]
    services              = ["application-default"]
    action                = "allow"
  }
}
```

## Remediated example
```hcl
resource "panos_security_rule_group" "broad_allow" {
  rule {
    name                  = "allow-app-servers-to-dmz"
    source_zones          = ["trust"]
    destination_zones     = ["dmz"]
    source_addresses      = ["10.1.20.0/24"]
    destination_addresses = ["any"]
    applications           = ["web-browsing", "ssl"]
    services              = ["application-default"]
    action                = "allow"
  }
}
```

## Remediation steps
1. Identify the actual source hosts/subnets or destination hosts/subnets the rule is meant to serve.
2. Constrain at least one of `source_addresses` or `destination_addresses` to a specific address object, subnet, or address group rather than `any`.
3. Prefer constraining the side that is more stable/known (e.g., a fixed set of application servers) over the side that may legitimately vary (e.g., arbitrary internet destinations for outbound web browsing).
4. For truly internet-facing egress rules where the destination cannot be enumerated, ensure the source side is tightly scoped instead.
5. Re-validate the rule order in the PAN-OS rulebase after tightening — a subsequent broader rule could still shadow the fix.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/PolicyNoSrcAnyDstAny.py)
- [Checkov check source (Ansible graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyNoSrcAnyDstAny.json)
