# CKV_PAN_5: Ensure security rules do not have 'applications' set to 'any'

## Severity
**MEDIUM** (score: 5.0/10)

Setting `applications` to `any` disables App-ID enforcement for the rule, allowing any application (including tunneled or evasive traffic on an allowed port, e.g. a reverse shell over 443) to match and traverse the firewall unchecked.

## Summary
This check fails any Palo Alto Networks (PAN-OS) security policy rule whose `applications` field permits `any`, since that disables application-layer identification and control for the rule.

## Applicability
- **Terraform**: resource types `panos_security_policy` and `panos_security_rule_group` (each `rule` block within them).
- **Ansible**: task `tasks.paloaltonetworks.panos.panos_security_rule` (attribute `application`), evaluated via a Checkov graph check.

## Why it matters
PAN-OS firewalls are App-ID capable — they can identify and enforce policy based on the actual application traversing the firewall (e.g., "salesforce", "ssh", "bittorrent") rather than just port/protocol. Setting `applications` to `any` disables this control for the rule, meaning any application — including tunneled, evasive, or unauthorized applications riding on an allowed port (e.g., a reverse shell over port 443) — will match and be permitted (or denied, but without granularity) by the rule. This defeats the primary value proposition of a next-generation firewall and turns the device into a simple stateful packet filter for that rule, widening the attack surface for application-layer threats, data exfiltration, and shadow IT usage.

## How Checkov evaluates this
**Terraform (`PolicyNoApplicationAny.py`)**: For each `rule` block in the resource:
- If the rule has no `applications` attribute at all → FAIL (this would also fail Terraform's own validation, but Checkov flags it defensively).
- If `applications` is present and its first value is exactly `"any"` → FAIL. (Terraform/PAN-OS provider semantics only allow `"any"` as a standalone value — it cannot be combined with other application names in the list.)
- Any other explicit application value(s) → PASS.
- If the resource defines no `rule` blocks at all → result is `UNKNOWN` (nothing to evaluate).

**Ansible (graph check `PanosPolicyNoApplicationAny.json`)**: Checks the `application` attribute on `tasks.paloaltonetworks.panos.panos_security_rule` tasks — it must (a) exist, (b) be non-empty, and (c) not equal `"any"` (case-insensitive).

## Non-compliant example
```hcl
resource "panos_security_rule_group" "web_egress" {
  rule {
    name                  = "allow-web-egress"
    source_zones          = ["trust"]
    source_addresses      = ["10.0.0.0/8"]
    destination_zones     = ["untrust"]
    destination_addresses = ["any"]
    applications           = ["any"]
    services              = ["application-default"]
    action                = "allow"
  }
}
```

## Remediated example
```hcl
resource "panos_security_rule_group" "web_egress" {
  rule {
    name                  = "allow-web-egress"
    source_zones          = ["trust"]
    source_addresses      = ["10.0.0.0/8"]
    destination_zones     = ["untrust"]
    destination_addresses = ["any"]
    applications           = ["ssl", "web-browsing"]
    services              = ["application-default"]
    action                = "allow"
  }
}
```

## Remediation steps
1. Identify the actual application(s) the rule is intended to permit (use PAN-OS App-ID visibility/traffic logs if unsure).
2. Replace `applications = ["any"]` with an explicit list of App-ID application names (e.g. `["ssl", "web-browsing", "dns"]`).
3. If truly open access is required for a transitional period, scope it as tightly as possible with source/destination and services, and treat the rule as temporary technical debt with a tracked remediation date.
4. Re-apply and validate in PAN-OS that the rule still permits the expected traffic (App-ID dependencies, e.g. `web-browsing` implicitly requiring `ssl`, can cause unexpected drops).
5. No provider version constraint beyond having the `panos` Terraform provider configured; no resource replacement is required — this is an in-place attribute update.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/PolicyNoApplicationAny.py)
- [Checkov check source (Ansible graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyNoApplicationAny.json)
