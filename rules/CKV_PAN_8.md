# CKV_PAN_8: Ensure description is populated within security policies

## Severity
**LOW** (score: 2.0/10)

A missing rule description is a documentation/hygiene gap that hampers auditability and change management but does not by itself open or widen an attack path.

## Summary
This check fails a Palo Alto Networks (PAN-OS) security policy rule that has no `description` (or an empty/blank one), enforcing that every rule documents its intent.

## Applicability
- **Terraform**: resource types `panos_security_policy` and `panos_security_rule_group` (each `rule` block, attribute `description`).
- **Ansible**: task `tasks.paloaltonetworks.panos.panos_security_rule` (attribute `description`), evaluated via a Checkov graph check.

## Why it matters
Firewall rulebases accumulate over years of change requests, and undocumented rules are a well-known operational and security liability: nobody can safely determine whether an undocumented rule is still needed, who requested it, or what it was meant to permit. This leads to "rule sprawl" — stale, overly permissive rules that are never removed because removing them is risky without knowing their purpose. From a security audit and change-management perspective (relevant to PCI-DSS requirement 1.1.6 and similar controls), every firewall rule should be traceable to a business justification. A populated `description` field is the mechanism for that traceability directly in the rule object, independent of external ticketing systems that may become disconnected from the actual configuration over time.

## How Checkov evaluates this
**Terraform (`PolicyDescription.py`)**: For each `rule` block:
- If `description` is missing entirely → FAIL.
- If `description` is present but, after stripping whitespace, is an empty string → FAIL.
- Any non-blank description → PASS.
- If the resource has no `rule` blocks → result is `UNKNOWN`.

**Ansible (graph check `PanosPolicyDescription.json`)**: Requires the `description` attribute on `tasks.paloaltonetworks.panos.panos_security_rule` to exist and be non-empty.

## Non-compliant example
```hcl
resource "panos_security_rule_group" "app_rule" {
  rule {
    name                  = "allow-app-db"
    source_zones          = ["app"]
    destination_zones     = ["db"]
    source_addresses      = ["10.1.10.0/24"]
    destination_addresses = ["10.1.30.10/32"]
    applications           = ["mysql"]
    services              = ["application-default"]
    action                = "allow"
    # no description set
  }
}
```

## Remediated example
```hcl
resource "panos_security_rule_group" "app_rule" {
  rule {
    name                  = "allow-app-db"
    source_zones          = ["app"]
    destination_zones     = ["db"]
    source_addresses      = ["10.1.10.0/24"]
    destination_addresses = ["10.1.30.10/32"]
    applications           = ["mysql"]
    services              = ["application-default"]
    action                = "allow"
    description           = "Allow app-tier servers to reach MySQL DB tier. Ticket: CHG-4821."
  }
}
```

## Remediation steps
1. Add a `description` attribute to every `rule` block.
2. Include, at minimum: the business purpose of the rule and, ideally, a change-ticket/reference ID for traceability.
3. As an org-wide practice, enforce this via a pre-commit/CI Checkov gate rather than relying on manual review, since rule descriptions are easy to omit under time pressure.
4. When bulk-remediating an existing rulebase, treat any rule you cannot confidently describe as a candidate for a rule-cleanup/decommission review rather than inventing a placeholder description.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/PolicyDescription.py)
- [Checkov check source (Ansible graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyDescription.json)
