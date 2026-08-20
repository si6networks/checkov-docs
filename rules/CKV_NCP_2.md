# CKV_NCP_2: Ensure every access control groups rule has a description

## Severity
**LOW** (score: 2.0/10)

Requiring a description on access-control-group rules is a documentation/hygiene practice that aids auditability but does not itself change what traffic the rule permits or blocks.

## Summary
This check ensures that Naver Cloud Platform (NCP) Access Control Group resources (`ncloud_access_control_group`, `ncloud_access_control_group_rule`) — NCP's equivalent of a security group — have a `description` on the group itself or on each of its inbound/outbound rules, documenting why the rule exists.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `ncloud_access_control_group`, `ncloud_access_control_group_rule`
- **Check type:** resource-configuration check (Python)

## Why it matters
Access control group rules define which network traffic is allowed to/from an instance — they are one of the most security-critical artifacts in cloud infrastructure. Without a description, a rule that opens a port or CIDR range becomes an unexplained black box: months later, no one on the team knows whether "allow 10.20.0.0/16 on 5432" was for a specific partner integration, a temporary debugging session that was never cleaned up, or a mistake. This directly increases the risk of firewall rule sprawl, where overly permissive or forgotten rules persist indefinitely because no one is confident enough to remove them, and it slows down incident response and security audits since analysts must reverse-engineer intent from IP ranges and ports alone. Mandating descriptions turns the firewall configuration into self-documenting change history.

## How Checkov evaluates this
The check first looks for a `description` on the resource's `group_or_rule_description` (i.e. the top-level `description` attribute of the `conf` block) — if present, PASS.
If the resource has no `type` key (indicating it may define inline `inbound`/`outbound` rule blocks, as with `ncloud_access_control_group`), Checkov additionally checks whether **every** rule in the `outbound` list and **every** rule in the `inbound` list has its own non-empty `description`:
- It PASSES if the group-level `description` is set, **or** if both an inbound rule and an outbound rule with descriptions are found.
- Otherwise it FAILS.
For `ncloud_access_control_group_rule` (which has a `type` key), only the top-level `description` presence is checked.

## Non-compliant example
```hcl
resource "ncloud_access_control_group" "app_acg" {
  name   = "app-acg"
  vpc_no = ncloud_vpc.main.vpc_no
  # no description

  inbound {
    protocol   = "TCP"
    port_range = "443"
    ip_block   = "0.0.0.0/0"
    # no description on the rule either
  }
}
```

## Remediated example
```hcl
resource "ncloud_access_control_group" "app_acg" {
  name        = "app-acg"
  vpc_no      = ncloud_vpc.main.vpc_no
  description = "ACG for app tier; allows HTTPS from internet, restricts internal DB access"

  inbound {
    protocol    = "TCP"
    port_range  = "443"
    ip_block    = "0.0.0.0/0"
    description = "Public HTTPS access for the app frontend"
  }
}
```

## Remediation steps
1. Add a `description` attribute to every `ncloud_access_control_group` resource summarizing its overall purpose.
2. Additionally add a `description` to each individual `inbound`/`outbound` rule block (and to standalone `ncloud_access_control_group_rule` resources) explaining the specific reason for that rule — e.g. which service, team, or integration needs it.
3. Establish a lint/PR-review convention requiring a ticket reference or owner name in the description so rules can be traced back to their justification later.
4. During periodic firewall reviews, use missing or stale descriptions as a signal to re-evaluate whether a rule is still needed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/AccessControlGroupRuleDescription.py)
- [Naver Cloud Terraform provider: ncloud_access_control_group](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/access_control_group)
