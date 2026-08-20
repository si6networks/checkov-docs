# CKV_PAN_10: Ensure logging at session end is enabled within security policies
## Severity
**LOW** (score: 2.0/10)

Disabling end-of-session logging in security policies removes visibility into completed network sessions, hampering incident detection and forensic investigation of a firewall's traffic without directly enabling an attack path.

## Summary
This check ensures PAN-OS security policy rules keep "Log at Session End" (`log_end`) enabled, so that traffic sessions matching the rule are logged when the session terminates.

## Applicability
Terraform resources `panos_security_policy` and `panos_security_rule_group`, and Ansible task `tasks.paloaltonetworks.panos.panos_security_rule` (Python resource check for Terraform, graph-based JSON policy for Ansible).

## Why it matters
`log_end` controls whether the firewall generates a traffic log entry when a session matching this security rule closes. This is the standard, complete way PAN-OS records traffic activity — the log entry includes final byte/packet counts, session duration, and the disposition of the flow. Disabling it means:

- Sessions permitted or denied by that rule leave no traffic log record, creating a blind spot for security monitoring, incident response, and forensic investigation.
- SIEM correlation, threat hunting, and compliance reporting (e.g., PCI-DSS logging requirements) that depend on complete traffic logs will silently miss activity matched by this rule.
- If an attacker (or a misconfigured automation) disables logging on a rule as a precursor to abusing the access it grants, the absence of session-end logs removes the primary evidence trail investigators would otherwise rely on.
- Session-end logging is the PAN-OS default and the baseline expectation for security policy rules; explicitly disabling it on a rule is both unusual and a red flag during audits.

## How Checkov evaluates this
**Terraform** (`PolicyLoggingEnabled`, a `BaseResourceCheck`): iterates over each `rule` block inside `panos_security_policy`/`panos_security_rule_group` resources.
- For each rule, if `log_end` is present and set to a falsy value, **FAIL**.
- If `log_end` is absent for a rule, the PAN-OS default is `true`, so it's treated as compliant.
- **PASS** overall if no rule explicitly disables it; **UNKNOWN** if the resource defines no `rule` blocks.

**Ansible** (graph-based JSON policy `PanosPolicyLoggingEnabled.json`): a single condition on `tasks.paloaltonetworks.panos.panos_security_rule` tasks —
- **PASS** if `log_end` is not equal to `false` (covers both "attribute absent" and "explicitly true").
- **FAIL** only when `log_end` is explicitly set to `false`.

## Non-compliant example
```hcl
resource "panos_security_policy" "trust_to_untrust" {
  rule {
    name               = "allow-web-egress"
    source_zones       = ["trust"]
    destination_zones  = ["untrust"]
    applications       = ["web-browsing"]
    action             = "allow"
    log_end            = false   # session-end logging disabled
  }
}
```

```yaml
# Ansible
- name: Configure security rule
  paloaltonetworks.panos.panos_security_rule:
    rule_name: allow-web-egress
    source_zone: [trust]
    destination_zone: [untrust]
    application: [web-browsing]
    action: allow
    log_end: false   # session-end logging disabled
```

## Remediated example
```hcl
resource "panos_security_policy" "trust_to_untrust" {
  rule {
    name               = "allow-web-egress"
    source_zones       = ["trust"]
    destination_zones  = ["untrust"]
    applications       = ["web-browsing"]
    action             = "allow"
    log_end            = true   # session-end logging retained
  }
}
```

```yaml
# Ansible
- name: Configure security rule
  paloaltonetworks.panos.panos_security_rule:
    rule_name: allow-web-egress
    source_zone: [trust]
    destination_zone: [untrust]
    application: [web-browsing]
    action: allow
    log_end: true   # session-end logging retained
```

## Remediation steps
1. Remove any explicit `log_end = false` from security rules, or set it to `true`.
2. Confirm a log-forwarding profile is attached to the rule so session-end logs actually reach your SIEM/log collector, not just the local firewall log store.
3. Audit deployed PAN-OS configuration for rules where logging was disabled outside of IaC (via UI/API drift) as this check only covers what's declared in code.
4. Consider also enabling `log_start` selectively for rules needing session-start visibility (see CKV_PAN_16 for the tradeoffs), though session-end logging should remain the default baseline for nearly all rules.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/PolicyLoggingEnabled.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyLoggingEnabled.json
- PAN-OS Terraform provider `panos_security_policy` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/security_policy
