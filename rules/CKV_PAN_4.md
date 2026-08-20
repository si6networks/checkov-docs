# CKV_PAN_4: Ensure DSRI is not enabled within security policies
## Severity
**MEDIUM** (score: 5.0/10)

Enabling DSRI (Disable Server Response Inspection) in a security policy turns off inspection of server-to-client traffic, allowing malicious or policy-violating content in server responses to pass the firewall undetected.

## Summary
This check ensures PAN-OS security policy rules do not enable "Disable Server Response Inspection" (DSRI), which if turned on skips content/threat inspection of server-to-client traffic.

## Applicability
**Checkov framework(s):** `ansible`, `terraform`

Terraform resources `panos_security_policy` and `panos_security_rule_group`, and Ansible task `tasks.paloaltonetworks.panos.panos_security_rule` (implemented as a Python resource check for Terraform and a graph-based JSON policy for Ansible).

## Why it matters
PAN-OS security rules normally apply full content inspection (App-ID, threat prevention, antivirus, URL filtering, etc.) bidirectionally — both to client-to-server and server-to-client traffic within a session. DSRI (`disable_server_response_inspection`) is a rule-level option that, when enabled, tells the firewall to skip inspecting the server's responses back to the client, inspecting only the client-to-server direction.

Enabling DSRI creates a meaningful detection gap:

- Malware, exploit payloads, or malicious content delivered from a compromised or malicious server to a client (e.g., a drive-by download, a malicious response to a legitimate-looking request, data exfiltration disguised as a normal response) will not be inspected or blocked by threat prevention/antivirus profiles attached to that rule.
- It undermines defense-in-depth: an organization may believe threat prevention is fully applied to a flow because a security profile is attached to the rule, while DSRI silently exempts half of the traffic direction from that inspection.
- DSRI was originally intended as a performance optimization for very high-throughput data-center flows where response inspection was deemed unnecessary (e.g. known trusted internal servers), but applying it broadly (or by mistake) removes protection against server-side compromise or malicious upstream content for that traffic.

## How Checkov evaluates this
**Terraform** (`PolicyNoDSRI`, a `BaseResourceCheck`): iterates over each `rule` block inside `panos_security_policy`/`panos_security_rule_group` resources.
- For each rule, if `disable_server_response_inspection` is set to a truthy value, **FAIL**.
- If the attribute is absent for a rule, or explicitly `false`, that rule is compliant (default is `false`, which is safe).
- **PASS** overall if no rule sets it to `true`; **UNKNOWN** if the resource has no `rule` blocks to evaluate.

**Ansible** (graph-based JSON policy `PanosPolicyNoDSRI.json`): evaluates `tasks.paloaltonetworks.panos.panos_security_rule` tasks with an `or` condition —
- **PASS** if `disable_server_response_inspection` equals `false`, OR if the attribute does not exist at all.
- **FAIL** only when it is explicitly set to `true`.

## Non-compliant example
```hcl
resource "panos_security_policy" "trust_to_untrust" {
  rule {
    name                               = "allow-web-egress"
    source_zones                       = ["trust"]
    destination_zones                  = ["untrust"]
    applications                       = ["web-browsing"]
    action                             = "allow"
    disable_server_response_inspection = true   # server-to-client inspection skipped
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
    disable_server_response_inspection: true   # server-to-client inspection skipped
```

## Remediated example
```hcl
resource "panos_security_policy" "trust_to_untrust" {
  rule {
    name                               = "allow-web-egress"
    source_zones                       = ["trust"]
    destination_zones                  = ["untrust"]
    applications                       = ["web-browsing"]
    action                             = "allow"
    disable_server_response_inspection = false   # full bidirectional inspection retained
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
    disable_server_response_inspection: false   # full bidirectional inspection retained
```

## Remediation steps
1. Set `disable_server_response_inspection = false` (or simply omit the attribute, since the default is safe) on every security rule.
2. If DSRI was enabled intentionally for a performance reason on a specific known-trusted high-throughput flow, document the exception and scope it as narrowly as possible (specific source/destination/application), rather than applying it broadly.
3. Ensure threat prevention, antivirus, and URL filtering security profiles are attached to the rule and verify (via logs) that server-to-client traffic is actually being inspected after the change.
4. Audit existing deployed PAN-OS configuration (not just Terraform/Ansible source) for drift, since this setting can also be toggled directly in Panorama/firewall UI outside of IaC.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/PolicyNoDSRI.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyNoDSRI.json
- PAN-OS Terraform provider `panos_security_policy` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/security_policy
