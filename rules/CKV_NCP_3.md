# CKV_NCP_3: Ensure no security group rules allow outbound traffic to 0.0.0.0/0
## Severity
**MEDIUM** (score: 5.5/10)

Unrestricted outbound access to 0.0.0.0/0 lacks network egress segmentation, increasing the risk of data exfiltration or command-and-control communication if a host is compromised.

## Summary
This check fails an NCloud `ncloud_access_control_group_rule` resource whenever it contains an outbound rule permitting traffic to any destination (`0.0.0.0/0` for IPv4 or `::/0` for IPv6).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_access_control_group_rule`
- **Check type:** resource (custom `scan_resource_conf` logic)

## Why it matters
Unrestricted outbound access ("allow all egress") is a common but risky default. If an instance behind the Access Control Group (ACG) is ever compromised (via a vulnerable application, supply-chain dependency, or leaked credentials), unrestricted egress lets the attacker freely exfiltrate data to any external endpoint, establish command-and-control (C2) channels, download additional malicious tooling, or use the instance as a launchpad to attack other systems on the internet. Restricting outbound traffic to only the specific destinations and ports an application legitimately needs (a default-deny egress posture) significantly limits the blast radius of a compromise and is a standard defense-in-depth control expected in mature cloud security baselines.

## How Checkov evaluates this
The check implements a custom `scan_resource_conf` method (not a simple attribute lookup):
```python
for idx, outbound in enumerate(conf.get("outbound", [])):
    ip = outbound.get("ip_block")
    if ip == ["0.0.0.0/0"] or ip == ["::/0"]:
        return CheckResult.FAILED
return CheckResult.PASSED
```
- It iterates over every `outbound` block defined in the resource.
- **FAIL:** any outbound block's `ip_block` is exactly `0.0.0.0/0` or `::/0` (i.e., every possible destination address).
- **PASS:** no outbound block targets an unrestricted destination CIDR (or the resource has no outbound blocks at all).
- Note the check only flags the case where `ip_block` matches the "any" CIDR exactly as a single-element list — it does not evaluate port/protocol scoping within that unrestricted rule.

## Non-compliant example
```hcl
resource "ncloud_access_control_group_rule" "app_egress" {
  access_control_group_no = ncloud_access_control_group.app_acg.id

  outbound {
    protocol    = "TCP"
    ip_block    = "0.0.0.0/0"
    port_range  = "1-65535"
    description = "Allow all outbound"
  }
}
```

## Remediated example
```hcl
resource "ncloud_access_control_group_rule" "app_egress" {
  access_control_group_no = ncloud_access_control_group.app_acg.id

  outbound {
    protocol    = "TCP"
    ip_block    = "10.0.1.0/24"   # only the internal DB subnet
    port_range  = "5432"
    description = "Allow Postgres egress to internal DB subnet only"
  }

  outbound {
    protocol    = "TCP"
    ip_block    = "203.0.113.10/32"  # a specific external API endpoint
    port_range  = "443"
    description = "Allow HTTPS egress to the specific third-party API"
  }
}
```

## Remediation steps
1. Identify the actual destinations, ports, and protocols the workload needs to reach (internal databases, package/OS update mirrors, specific third-party APIs).
2. Replace the `0.0.0.0/0` outbound rule with one or more scoped rules targeting only those specific CIDR ranges/hosts and ports.
3. If broad outbound HTTPS is unavoidable (e.g., calling many unpredictable external endpoints), consider routing egress through a forward proxy or NAT gateway that can be centrally monitored/logged, and restrict the ACG to only that egress path.
4. Re-validate application connectivity after tightening rules — outbound restrictions can break DNS resolution, NTP, package manager updates, or third-party SDK calls if not scoped correctly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/AccessControlGroupOutboundRule.py)
