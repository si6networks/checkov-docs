# CKV_NCP_25: Ensure no access control groups allow inbound from 0.0.0.0:0 to port 80
## Severity
**MEDIUM** (score: 5.0/10)

Allowing inbound access from 0.0.0.0/0 on port 80 exposes an unencrypted HTTP service broadly, but port 80 is commonly intended to be public for web traffic, limiting the incremental risk versus administrative or database ports.

## Summary
This check fails any NCloud Access Control Group rule (`ncloud_access_control_group_rule`) that permits inbound traffic on port 80 (HTTP) from the entire internet (`0.0.0.0/0`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_access_control_group_rule`
- **Check type:** resource (subclass of the shared `AccessControlGroupInboundRule` base check, parameterized with `port=80`)

## Why it matters
Port 80 typically serves an unencrypted HTTP endpoint. Leaving it open to `0.0.0.0/0` at the network security-group layer means any host on the internet can reach the service directly, which is appropriate only for genuinely public web front ends — and even then it should usually be fronted by a load balancer/WAF rather than exposed on individual instances' ACG rules. When port 80 is opened broadly on instance-level or subnet-level ACGs unintentionally (e.g., a rule meant to be scoped to a load balancer's IP range but left as `0.0.0.0/0`), it allows any external actor to probe for a running web server, exploit unpatched web application vulnerabilities, or use it as a reconnaissance/pivot point without the segmentation that ACGs are meant to provide.

## How Checkov evaluates this
This check is implemented as a subclass of the shared `AccessControlGroupInboundRule` base class, initialized with `port=80`. The base class logic (shared with the port 22 and 3389 variants) inspects each inbound rule block of an `ncloud_access_control_group_rule` resource and fails the check when both of these are true for a rule:
- The rule's source `ip_block` is `0.0.0.0/0` (or an equivalent "any" CIDR).
- The rule's port range (a single port or a range, e.g., `80` or `1-1000`) includes port 80.

If the rule restricts the source CIDR to a smaller range, or the port range does not cover 80, the rule passes.

## Non-compliant example
```hcl
resource "ncloud_access_control_group" "web_acg" {
  name        = "web-acg"
  description = "ACG for web tier"
  vpc_no      = ncloud_vpc.example.vpc_no
}

resource "ncloud_access_control_group_rule" "inbound_http" {
  access_control_group_no = ncloud_access_control_group.web_acg.id

  inbound {
    protocol    = "TCP"
    ip_block    = "0.0.0.0/0"
    port_range  = "80"
    description = "Allow HTTP from anywhere"
  }
}
```

## Remediated example
```hcl
resource "ncloud_access_control_group" "web_acg" {
  name        = "web-acg"
  description = "ACG for web tier"
  vpc_no      = ncloud_vpc.example.vpc_no
}

resource "ncloud_access_control_group_rule" "inbound_http" {
  access_control_group_no = ncloud_access_control_group.web_acg.id

  inbound {
    protocol    = "TCP"
    ip_block    = "10.0.0.0/16"   # restricted to the load balancer / internal subnet
    port_range  = "80"
    description = "Allow HTTP only from the internal LB subnet"
  }
}
```

## Remediation steps
1. Scope the inbound rule's `ip_block` to the smallest CIDR range that legitimately needs port 80 access (e.g., the load balancer's subnet, a known partner network, or a specific IP), rather than `0.0.0.0/0`.
2. If the resource genuinely must be a public-facing web endpoint, move the exposed listener to a load balancer (see `ncloud_lb_listener`) and restrict the backend instances' ACG to only accept traffic from the load balancer's internal IP range.
3. Consider redirecting all port 80 traffic to HTTPS (port 443) instead of terminating unencrypted traffic directly, and restrict ACG rules accordingly.
4. Re-run Checkov after the change to confirm the rule no longer matches `0.0.0.0/0` for port 80.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/AccessControlGroupInboundRulePort80.py)
