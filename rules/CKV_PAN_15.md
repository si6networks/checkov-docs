# CKV_PAN_15: Ensure an Include ACL is defined for a Zone when User-ID is enabled
## Severity
**LOW** (score: 2.0/10)

Enabling User-ID on a zone without a restrictive Include ACL lets the firewall accept IP-address-to-username mapping information from an unbounded set of sources, risking spoofed identity mappings that cause security policies to be enforced against the wrong user.

## Summary
This check ensures that whenever User-ID is enabled on a PAN-OS Security Zone, an Include ACL restricting which source subnets User-ID actively maps to usernames is also defined, so that user mapping doesn't apply indiscriminately to every host in the zone.

## Applicability
Terraform resources `panos_zone` and `panos_panorama_zone`, and Ansible task `tasks.paloaltonetworks.panos.panos_zone` (Python resource check for Terraform, graph-based JSON policy for Ansible).

## Why it matters
User-ID is the PAN-OS feature that maps observed source IP addresses to usernames, enabling security policy rules and logs to be written in terms of users/groups rather than raw IPs. When User-ID is enabled on a zone without an Include ACL scoping which subnets it should actively monitor:

- User-ID will attempt to map every IP address observed in that zone to a user, including addresses that may not correspond to real managed endpoints (e.g., guest networks, shared/NAT'd addresses, IoT devices, or ranges outside the organization's control that happen to route through the zone).
- This wastes User-ID mapping table resources and processing on irrelevant address space, and can produce incorrect or stale user-to-IP mappings for shared/NAT'd source addresses (multiple users appearing to be "one user" behind a NAT gateway, or a mapping persisting after a DHCP lease reassigns an IP to a different user).
- Incorrect user mappings directly weaken the security value of any User-ID-based policy rule: if policy allows "finance-group" access based on a stale or wrong IP-to-user mapping, an unauthorized user on that IP could inherit access intended for someone else, or legitimate access could be unexpectedly denied.
- Explicitly scoping the Include ACL to only the subnets containing real managed user endpoints (e.g., the corporate LAN DHCP range) ensures mapping accuracy and keeps User-ID's authoritative scope intentional rather than incidental.

## How Checkov evaluates this
**Terraform** (`ZoneUserIDIncludeACL`, a `BaseResourceCheck`): reads `enable_user_id` and, if enabled, checks `include_acls`.
- If `enable_user_id` is falsy/absent, **PASS** (the Include ACL requirement doesn't apply when User-ID isn't enabled).
- If `enable_user_id` is truthy, **FAIL** if `include_acls` is absent.
- If `include_acls` is present, iterate its entries: **FAIL** if any entry is an empty string.
- **PASS** if User-ID is enabled and `include_acls` is present with no empty entries.

**Ansible** (graph-based JSON policy `PanosZoneUserIDIncludeACL.json`): an `or` of two branches on `tasks.paloaltonetworks.panos.panos_zone` tasks —
- **PASS** if `enable_userid` does not exist (User-ID not enabled, requirement doesn't apply).
- **PASS** if `enable_userid` equals `true` AND `include_acl` exists AND is non-empty.
- **FAIL** otherwise (User-ID enabled but Include ACL missing or empty).

Note: the Terraform implementation reads `enable_user_id`/`include_acls` (with underscores) while the Ansible graph policy targets `enable_userid`/`include_acl` — these map to the differing attribute-naming conventions of each tool's underlying schema.

## Non-compliant example
```hcl
resource "panos_zone" "trust" {
  name           = "trust"
  mode           = "layer3"
  enable_user_id = true
  # include_acls intentionally omitted -- User-ID maps every host in the zone
}
```

```yaml
# Ansible
- name: Configure security zone
  paloaltonetworks.panos.panos_zone:
    zone_name: trust
    mode: layer3
    enable_userid: true
    # include_acl omitted
```

## Remediated example
```hcl
resource "panos_zone" "trust" {
  name           = "trust"
  mode           = "layer3"
  enable_user_id = true
  include_acls   = ["10.0.10.0/24"]   # scoped to the corporate LAN subnet only
}
```

```yaml
# Ansible
- name: Configure security zone
  paloaltonetworks.panos.panos_zone:
    zone_name: trust
    mode: layer3
    enable_userid: true
    include_acl: ["10.0.10.0/24"]     # scoped to the corporate LAN subnet only
```

## Remediation steps
1. For every zone with `enable_user_id`/`enable_userid` set to `true`, add an Include ACL naming the specific subnet(s) containing real, managed user endpoints.
2. Avoid empty-string entries in the ACL list — each entry should be a concrete CIDR/IP range.
3. Add an Exclude ACL as well for any known shared/NAT/infrastructure addresses within the included range that should not be mapped (e.g., a NAT gateway IP).
4. Where User-ID isn't actually needed for a zone, disable `enable_user_id` instead of leaving it on with an unscoped ACL.
5. Periodically review User-ID mapping accuracy (via `show user ip-user-mapping all` or Panorama monitoring) to confirm the ACL scope still matches your real endpoint address ranges as network topology evolves.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/panos/ZoneUserIDIncludeACL.py
- Checkov check source (Ansible): https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/PanosZoneUserIDIncludeACL.json
- PAN-OS Terraform provider `panos_zone` reference: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest/docs/resources/zone
