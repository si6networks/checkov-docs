# CKV_PAN_9: Ensure a Log Forwarding Profile is selected for each security policy rule

## Severity
**LOW** (score: 2.0/10)

Without a Log Forwarding profile, traffic matched by the rule never reaches the SIEM/SOC tooling, creating a genuine detection and incident-response blind spot for that traffic.

## Summary
This check fails a Palo Alto Networks (PAN-OS) security policy rule that does not have a Log Forwarding profile (`log_setting`) attached, meaning traffic matched by that rule is not forwarded to an external logging/SIEM destination.

## Applicability
- **Terraform**: resource types `panos_security_policy` and `panos_security_rule_group` (each `rule` block, attribute `log_setting`).
- **Ansible**: task `tasks.paloaltonetworks.panos.panos_security_rule` (attribute `log_setting`), evaluated via a Checkov graph check.

## Why it matters
PAN-OS retains traffic/threat logs locally, but without a Log Forwarding profile, that log data never reaches a centralized SIEM, log-retention platform, or SOC tooling. This directly undermines detection and response capability: security monitoring, alerting rules, and correlation searches that live in the SIEM simply never see traffic matched by rules missing `log_setting`. It also creates compliance gaps for standards requiring centralized, tamper-resistant log retention (e.g., PCI-DSS logging requirements, SOC 2 monitoring controls) — logs sitting only on the firewall's local disk are subject to rotation/loss and are not independently auditable. In an incident response scenario, a rule without forwarded logging is effectively a blind spot: traffic could be flowing through it (permitted or denied) with no visibility outside the firewall itself.

## How Checkov evaluates this
**Terraform (`PolicyLogForwarding.py`)**: For each `rule` block:
- If `log_setting` is missing entirely → FAIL.
- If `log_setting` is present but, after stripping whitespace, is an empty string → FAIL.
- Any non-blank `log_setting` value (the name of a configured Log Forwarding profile) → PASS.
- If the resource has no `rule` blocks → result is `UNKNOWN`.

**Ansible (graph check `PanosPolicyLogForwarding.json`)**: Requires the `log_setting` attribute on `tasks.paloaltonetworks.panos.panos_security_rule` to exist and be non-empty.

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
    description           = "Allow app-tier servers to reach MySQL DB tier."
    # no log_setting set
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
    description           = "Allow app-tier servers to reach MySQL DB tier."
    log_setting           = "forward-to-siem"
  }
}
```

## Remediation steps
1. Confirm a Log Forwarding profile (e.g., `forward-to-siem`) is already configured on the PAN-OS device/Panorama pointing at your SIEM/syslog destination.
2. Add `log_setting = "<profile-name>"` to every `rule` block that lacks one.
3. Verify `log_start`/`log_end` behavior is also as desired (Checkov does not check these here, but they control whether session start and/or end events are logged) — typically enabling "log at session end" is the minimum needed for the forwarding profile to have data to send.
4. Apply org-wide via a shared/common rule group or Panorama template if you manage many firewalls, to avoid per-rule drift.
5. No provider version constraint or resource replacement required — this is an in-place attribute addition.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/PolicyLogForwarding.py)
- [Checkov check source (Ansible graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyLogForwarding.json)
