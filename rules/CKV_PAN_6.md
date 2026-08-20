# CKV_PAN_6: Ensure security rules do not have 'services' set to 'any'

## Severity
**LOW** (score: 2.0/10)

Setting `services` to `any` removes the port/protocol-based secondary control, so the rule matches traffic on every port, widening exposure and removing the only backstop against App-ID misclassification.

## Summary
This check fails any Palo Alto Networks (PAN-OS) security policy rule whose `services` field permits `any`, since that allows the rule to match traffic on every TCP/UDP port rather than the specific ports/services it is meant to control.

## Applicability
**Checkov framework(s):** `ansible`, `terraform`

- **Terraform**: resource types `panos_security_policy` and `panos_security_rule_group` (each `rule` block within them).
- **Ansible**: task `tasks.paloaltonetworks.panos.panos_security_rule` (attribute `service`), evaluated via a Checkov graph check.

## Why it matters
Restricting `services` (the port/protocol service objects, e.g. `application-default`, `tcp-443`) is a defense-in-depth control that operates independently of App-ID. When `services` is set to `any`, the rule matches traffic on any port/protocol combination, which:
- Allows applications to run on non-standard ports, undermining port-based segmentation assumptions made elsewhere in the network.
- Increases the blast radius of a misconfigured or bypassed App-ID classification, since App-ID misidentification combined with `services = any` means there is no secondary port-based check to catch the traffic.
- Makes the rule effectively a "allow all ports between these zones/addresses" rule, which is far broader than most business rules require and complicates auditing/incident response (you cannot tell from the policy alone which ports are actually expected).

## How Checkov evaluates this
**Terraform (`PolicyNoServiceAny.py`)**: For each `rule` block in the resource:
- If `services` is missing entirely → FAIL.
- If `services` is present and its first value is exactly `"any"` → FAIL. (PAN-OS/Terraform semantics only allow `"any"` standalone in the list, never combined with other service names.)
- Any explicit service name(s) (e.g. `application-default`, custom service objects) → PASS.
- If the resource has no `rule` blocks → result is `UNKNOWN`.

**Ansible (graph check `PanosPolicyNoServiceAny.json`)**: Checks the `service` attribute on `tasks.paloaltonetworks.panos.panos_security_rule` — must exist, be non-empty, and not equal `"any"` (case-insensitive).

## Non-compliant example
```hcl
resource "panos_security_rule_group" "web_egress" {
  rule {
    name                  = "allow-web-egress"
    source_zones          = ["trust"]
    destination_zones     = ["untrust"]
    source_addresses      = ["10.0.0.0/8"]
    destination_addresses = ["any"]
    applications           = ["web-browsing", "ssl"]
    services              = ["any"]
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
    destination_zones     = ["untrust"]
    source_addresses      = ["10.0.0.0/8"]
    destination_addresses = ["any"]
    applications           = ["web-browsing", "ssl"]
    services              = ["application-default"]
    action                = "allow"
  }
}
```

## Remediation steps
1. Determine the expected port(s) for the rule's applications (PAN-OS's `application-default` service is usually the correct choice — it lets App-ID enforce the standard port per application).
2. Replace `services = ["any"]` with `["application-default"]` or an explicit list of PAN-OS service objects/custom ports.
3. If non-standard ports are legitimately required (e.g., an app running on a custom port), define a named custom service object and reference it instead of `any`.
4. Re-validate traffic flows after the change, since some legacy applications may break if they were relying on unrestricted ports.
5. No provider/resource replacement required — this is an in-place attribute change on the `rule` block.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/PolicyNoServiceAny.py)
- [Checkov check source (Ansible graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosPolicyNoServiceAny.json)
