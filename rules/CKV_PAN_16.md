# CKV_PAN_16: Ensure logging at session start is disabled within security policies except for troubleshooting and long lived GRE tunnels
## Severity
**LOW** (score: 2.0/10)

Leaving session-start logging enabled outside of troubleshooting/long-lived-GRE scenarios is primarily a logging-volume and operational-hygiene concern, since session-end logging already provides the security-relevant record of completed sessions.

## Summary
This check ensures that PAN-OS security policy rules do not enable "Log at Session Start" (`log_start`) by default, since session-start logging is intended only for narrow use cases (troubleshooting, long-lived GRE tunnels) and, if left broadly enabled, generates excessive/duplicate log volume.

## Applicability
**Checkov framework(s):** `ansible`

Ansible task `tasks.paloaltonetworks.panos.panos_security_rule` (this check is implemented only as a graph-based JSON policy for Ansible; no Terraform equivalent is listed).

## Why it matters
PAN-OS security rules can log at session start, session end, or both. Session-end logging (see CKV_PAN_10) is the standard, complete record of a session including final byte/packet counts and duration, and should generally remain enabled. Session-start logging, by contrast, generates an additional log entry the moment a session begins — before it's known how the session will conclude.

Enabling `log_start` broadly across rules causes:

- Log volume roughly doubling for every matched session (one entry at start, one at end), which increases log storage costs, ingestion load on downstream SIEM/log-forwarding pipelines, and noise that analysts must filter through during investigation.
- Redundant data for the vast majority of rules, since the session-end log already captures everything relevant (including the fact that a session started) — session-start logging adds value mainly for rules involving long-lived connections (e.g., a GRE tunnel that could stay open for hours/days, where you want to know it started even before the eventual "end" log arrives), or when actively troubleshooting a rule and need real-time visibility into session initiation.
- Because it's meant to be the exception rather than the rule, a security policy where `log_start` is enabled broadly (rather than narrowly, for the GRE-tunnel/troubleshooting cases) suggests either leftover troubleshooting configuration that was never reverted, or a misunderstanding of PAN-OS logging design intent — both of which should be reviewed.

## How Checkov evaluates this
This is a graph-based JSON policy (`PanosPolicyLogSessionStart.json`) evaluating `tasks.paloaltonetworks.panos.panos_security_rule` tasks with an `or` of two conditions:

- **PASS** if `log_start` is not equal to `true` (case-insensitive) — i.e., it's explicitly `false` or some other non-true value.
- **PASS** if `log_start` does not exist at all (the default for `log_start` is `false`, which is compliant).
- **FAIL** only when `log_start` is explicitly present and equals `true` (case-insensitive comparison, so `"True"`/`"TRUE"` also fail).

Note this is a broad rule-level check without an automated exception for the "troubleshooting or long-lived GRE tunnel" carve-out named in the policy's title — that judgment is left to the reviewer; the check simply flags every rule with `log_start: true` for manual review against that exception criteria.

## Non-compliant example
```yaml
# Ansible
- name: Configure security rule
  paloaltonetworks.panos.panos_security_rule:
    rule_name: allow-web-egress
    source_zone: [trust]
    destination_zone: [untrust]
    application: [web-browsing]
    action: allow
    log_start: true    # session-start logging enabled on a routine rule
    log_end: true
```

## Remediated example
```yaml
# Ansible
- name: Configure security rule
  paloaltonetworks.panos.panos_security_rule:
    rule_name: allow-web-egress
    source_zone: [trust]
    destination_zone: [untrust]
    application: [web-browsing]
    action: allow
    log_start: false   # session-start logging disabled for a routine, short-lived flow
    log_end: true
```

```yaml
# Justified exception: a long-lived GRE tunnel rule
- name: Configure GRE tunnel security rule
  paloaltonetworks.panos.panos_security_rule:
    rule_name: gre-tunnel-to-branch
    source_zone: [trust]
    destination_zone: [wan]
    application: [gre]
    action: allow
    log_start: true    # justified: long-lived tunnel, want visibility at session start
    log_end: true
```

## Remediation steps
1. Review every security rule with `log_start: true` and confirm whether it matches one of the two documented exceptions: active troubleshooting (temporary) or a long-lived GRE tunnel.
2. For rules that don't meet either exception, set `log_start: false` (or remove the attribute, since `false` is the default).
3. For temporary troubleshooting cases, track the change so it gets reverted once troubleshooting concludes — don't let it become permanent drift.
4. For legitimate long-lived-tunnel exceptions, document the justification inline (a comment in the playbook) so future reviewers understand why the rule is an intentional deviation from the general guidance.
5. Ensure `log_end` remains enabled on all rules regardless (see CKV_PAN_10), since it is the primary/complete logging mechanism this check assumes is already in place.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyLogSessionStart.json
- PAN-OS security policy rule reference (Ansible collection): https://galaxy.ansible.com/ui/repo/published/paloaltonetworks/panos/content/module/panos_security_rule/
