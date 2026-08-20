# CKV_YC_19: Ensure security group does not contain allow-all rules

## Severity
**CRITICAL** (score: 9.4/10)

A security group ingress rule allowing all protocols/ports from 0.0.0.0/0 removes network-layer access control entirely, exposing every service on the associated resources to unauthenticated internet-wide access.

## Summary
This check fails when a Yandex VPC security group (`yandex_vpc_security_group`) has an ingress rule that allows all ports from the entire internet (`0.0.0.0/0`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `yandex_vpc_security_group`

## Why it matters
An ingress rule that combines the source CIDR `0.0.0.0/0` (any host on the internet) with "all ports" (represented as `port = -1`, or an equivalent `from_port=0`/`to_port=65535` full range, or simply no port restriction specified at all) effectively removes all network-layer access control for anything attached to that security group. This is one of the most dangerous and common cloud misconfigurations: it exposes every service running on the associated resources — SSH, RDP, database ports, internal management APIs, debug endpoints — directly to anyone on the internet, regardless of whether those services were ever intended to be public. It eliminates defense-in-depth: even if an application has authentication bugs or an unpatched service is running on an unexpected port, this rule ensures it is reachable and attackable from anywhere.

## How Checkov evaluates this
The check (`VPCSecurityGroupAllowAll`) is a custom `BaseResourceCheck` (`scan_resource_conf`) that inspects the `ingress` block(s):
- It reads `ingress[0].v4_cidr_blocks` and iterates the CIDR list.
- If `0.0.0.0/0` is present:
  - If a `port` key is present and its value is `-1` (meaning "all ports"), the check **FAILS**.
  - If a `port` key is present with any other specific value, it **PASSES**.
  - If neither `from_port` nor `to_port` is present (and no `port`), the check **FAILS** (no restriction at all defaults to allow-all).
  - If `from_port == 0` and `to_port == 65535` (the full TCP/UDP port range), the check **FAILS**.
- In all other cases the check **PASSES**. Note: only the first `ingress` block (`ingress[0]`) is evaluated.

## Non-compliant example
```hcl
resource "yandex_vpc_security_group" "example" {
  name       = "app-sg"
  network_id = yandex_vpc_network.app.id

  ingress {
    protocol       = "ANY"
    port           = -1
    v4_cidr_blocks = ["0.0.0.0/0"]  # all ports from anywhere -- FAILS CKV_YC_19
  }
}
```

## Remediated example
```hcl
resource "yandex_vpc_security_group" "example" {
  name       = "app-sg"
  network_id = yandex_vpc_network.app.id

  ingress {
    protocol       = "TCP"
    port           = 443
    v4_cidr_blocks = ["0.0.0.0/0"]  # specific port only -- PASSES CKV_YC_19
  }
}
```

## Remediation steps
1. Remove any ingress rule that pairs `0.0.0.0/0` with `port = -1`, an unrestricted `from_port`/`to_port` range (0-65535), or no port restriction at all.
2. Restrict rules to specific, necessary ports (e.g., 443 for HTTPS) and, where possible, narrower source CIDR ranges than the full internet.
3. For management ports (SSH/22, RDP/3389, database ports), never expose them to `0.0.0.0/0` at all — restrict to specific admin/bastion IP ranges or use private connectivity (VPN, bastion host).
4. If a truly public service (e.g., a public web server) needs broad internet exposure, scope the rule to only the specific port(s) that service uses, not all ports.
5. Review all `ingress` blocks in the security group, not just the first — Checkov's evaluated logic only inspects the first ingress block, so manually audit additional blocks for the same allow-all pattern even if Checkov doesn't flag them.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/VPCSecurityGroupAllowAll.py)
- [Yandex Cloud VPC security groups documentation](https://yandex.cloud/en/docs/vpc/concepts/security-groups)
