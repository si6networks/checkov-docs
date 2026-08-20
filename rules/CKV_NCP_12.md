# CKV_NCP_12: An inbound Network ACL rule should not allow ALL ports

## Severity
**CRITICAL** (score: 9.0/10)

An inbound NACL rule spanning the full port range (1-65535) removes all port-level segmentation for the subnet, effectively opening every service on every host behind it to whatever source the rule allows.

## Summary
This check ensures that inbound rules on a Naver Cloud Platform (NCP) Network ACL (`ncloud_network_acl_rule`) do not use the full port range `1-65535`, which would allow traffic to any port on the destination.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_network_acl_rule`
- **Check type:** resource-configuration check (Python)

## Why it matters
A Network ACL rule that allows traffic to every port (`1-65535`) defeats the purpose of having granular network access control at all — it's functionally equivalent to no port restriction. Any service that happens to be listening on the affected host (including ones added later, misconfigured, or left running by mistake — databases, admin panels, debug interfaces, etc.) becomes reachable from whatever source the rule allows. This dramatically increases attack surface: instead of a small, reviewed set of expected ports, literally any listening service is exposed. Because NACLs apply at the subnet level, an "allow all ports" rule can expose every instance in that subnet's full port range at once, magnifying the blast radius of a single overly permissive rule.

## How Checkov evaluates this
The check inspects the `inbound` block(s) of the `ncloud_network_acl_rule` resource:
- For each inbound rule, if a `port_range` is present, Checkov checks whether any of its values equal the literal string `"1-65535"`.
  - If it does, the check **FAILS**.
  - If `port_range` is present and does not include `1-65535`, the check **PASSES**.
- If no `inbound` key is present at all, or `inbound` rules have no `port_range` key, the check **FAILS** (fails closed / conservative — treats missing port scoping as non-compliant).

## Non-compliant example
```hcl
resource "ncloud_network_acl_rule" "wide_open" {
  network_acl_no = ncloud_network_acl.main.id

  inbound {
    priority    = 100
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "10.0.0.0/16"
    port_range  = "1-65535"
  }
}
```

## Remediated example
```hcl
resource "ncloud_network_acl_rule" "scoped_https" {
  network_acl_no = ncloud_network_acl.main.id

  inbound {
    priority    = 100
    protocol    = "TCP"
    rule_action = "ALLOW"
    ip_block    = "10.0.0.0/16"
    port_range  = "443"
  }
}
```

## Remediation steps
1. Search for `ncloud_network_acl_rule` inbound rules with `port_range = "1-65535"`.
2. Replace the full-range port with the specific port(s) or a tight range actually required by the workload (e.g. `443`, `8080-8090`).
3. If multiple discrete ports are needed, define separate `inbound` rule entries rather than widening the range to cover everything in between.
4. Re-verify connectivity after tightening the range, since some multi-port protocols (e.g. passive FTP) may need a deliberately wider — but still bounded — range.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/NACLPortCheck.py)
- [Naver Cloud Terraform provider: ncloud_network_acl_rule](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/network_acl_rule)
