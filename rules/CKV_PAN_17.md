# CKV_PAN_17: Ensure security rules do not have 'source_zone' and 'destination_zone' both containing values of 'any'
## Severity
**MEDIUM** (score: 5.0/10)

A security rule with both source_zone and destination_zone set to 'any' effectively permits traffic between every zone the firewall manages, collapsing intended network segmentation into a single broad allow rule.

## Summary
This check ensures PAN-OS security policy rules do not set both `source_zone` and `destination_zone` to `any`, which would allow the rule to match traffic between every zone pair on the firewall rather than an intentional, scoped set of zones.

## Applicability
**Checkov framework(s):** `ansible`

Ansible task `tasks.paloaltonetworks.panos.panos_security_rule` (implemented only as a graph-based JSON policy for Ansible; no Terraform equivalent is listed).

## Why it matters
Security zones on PAN-OS are the fundamental unit of network segmentation the firewall enforces — traffic can only flow between zones according to security policy rules that explicitly permit it for a given source-zone/destination-zone pair. A rule with `source_zone: any` and `destination_zone: any` collapses this segmentation entirely for whatever action/application/service that rule specifies:

- It permits (or denies, depending on the rule's `action`) matching traffic between every zone combination on the device — trust-to-untrust, untrust-to-trust, DMZ-to-trust, trust-to-trust between different segments, etc. — as if zone boundaries didn't exist for that rule's scope.
- If the rule's action is `allow`, this effectively creates a segmentation bypass: traffic that should be blocked crossing from an untrusted zone into an internal zone (or vice versa) may instead be permitted because the rule wasn't scoped to specific zone pairs.
- It significantly increases the "blast radius" of a single rule — one overly broad `any`/`any` rule undermines the isolation that potentially dozens of more specific, correctly-scoped rules were designed to enforce elsewhere in the policy.
- Zone-pair scoping is one of PAN-OS's core defense-in-depth mechanisms (layered on top of application/user/content-based controls); using `any`/`any` for both source and destination zone effectively opts a rule out of that layer of control.

This pattern is a common but dangerous shortcut — often introduced during initial "get everything working" testing and never tightened afterward — and should be treated as a segmentation policy violation whenever it appears in a rule intended for production use.

## How Checkov evaluates this
This is a graph-based JSON policy (`PanosPolicyNoSrcZoneAnyNoDstZoneAny.json`) evaluating `tasks.paloaltonetworks.panos.panos_security_rule` tasks with an `or` of two branches (i.e., the rule passes if *either* the source zone or the destination zone is properly scoped away from "any"):

- **Branch 1 (source zone scoped)**: PASS if `source_zone` exists AND is non-empty AND is not equal to `"any"` (case-insensitive).
- **Branch 2 (destination zone scoped)**: PASS if `destination_zone` exists AND is non-empty AND is not equal to `"any"` (case-insensitive).
- **PASS** overall if either branch is satisfied — i.e., at least one of source or destination zone is a specific, non-"any" value.
- **FAIL** only when both `source_zone` and `destination_zone` are missing/empty/`"any"` simultaneously — meaning the rule truly has no zone restriction on either side.

## Non-compliant example
```yaml
# Ansible
- name: Configure security rule
  paloaltonetworks.panos.panos_security_rule:
    rule_name: allow-any-any
    source_zone: [any]         # no source zone restriction
    destination_zone: [any]    # no destination zone restriction
    application: [any]
    action: allow
```

## Remediated example
```yaml
# Ansible
- name: Configure security rule
  paloaltonetworks.panos.panos_security_rule:
    rule_name: allow-trust-to-untrust-web
    source_zone: [trust]           # scoped to a specific source zone
    destination_zone: [untrust]    # scoped to a specific destination zone
    application: [web-browsing, ssl]
    action: allow
```

## Remediation steps
1. Identify every security rule where both `source_zone` and `destination_zone` are `any` (or unset/empty, which the underlying PAN-OS default also treats as "any").
2. Replace at least one, and ideally both, with the specific zone(s) the rule is actually meant to cover.
3. If a rule genuinely needs to apply across many zones (e.g., a corporate-wide DNS-allow rule), enumerate the specific zones it should cover explicitly rather than using `any`, so future zone additions don't silently inherit unintended rule matches.
4. Re-order/re-scope the security policy so that any legitimate broad rules sit appropriately in the rulebase relative to more specific deny/allow rules (PAN-OS evaluates rules top-down, first match wins).
5. Audit logs for hit counts on any remaining `any`/`any`-style rules to understand what traffic they're actually matching before tightening, to avoid breaking legitimate flows.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyNoSrcZoneAnyNoDstZoneAny.json
- PAN-OS security policy rule reference (Ansible collection): https://galaxy.ansible.com/ui/repo/published/paloaltonetworks/panos/content/module/panos_security_rule/
