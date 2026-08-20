# CKV_NCP_23: Ensure Server instance should not have public IP
## Severity
**HIGH** (score: 7.5/10)

Attaching a public IP directly to a Server instance places it on the open internet, materially expanding the attack surface for any exposed services or vulnerabilities on that host.

## Summary
This check flags NCloud (Naver Cloud Platform) `ncloud_public_ip` resources whenever they are associated with a server instance, since attaching a public IP directly exposes the instance to the internet.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_public_ip`
- **Check type:** resource (single-resource attribute check)

## Why it matters
A public IP attached to a server instance makes it directly reachable from the internet, bypassing any network perimeter controls (NAT gateways, load balancers, bastion hosts) that would otherwise mediate access. Directly internet-facing compute instances are a much larger attack surface: they are subject to continuous internet-wide port scanning, brute-force login attempts, and exploitation of any exposed service (SSH, RDP, management consoles, application ports) without an intermediate choke point to apply access control, logging, or rate limiting. The recommended pattern is to keep servers on private subnets and expose only what is strictly necessary through a load balancer, bastion, or VPN gateway.

## How Checkov evaluates this
The check is implemented as a `BaseResourceNegativeValueCheck` that inspects the `server_instance_no` attribute of an `ncloud_public_ip` resource:
- It uses `ANY_VALUE` as the "forbidden value" for `server_instance_no`.
- **FAIL:** the `server_instance_no` attribute is set to any non-empty value — meaning the public IP resource is bound/associated to a specific server instance.
- **PASS:** `server_instance_no` is absent or empty — meaning the public IP resource exists (e.g., reserved) but is not attached to a server instance.

## Non-compliant example
```hcl
resource "ncloud_server" "web" {
  name                     = "web-server"
  server_image_product_code = "SW.VSVR.OS.LNX64.CNTOS.0708.B050"
}

resource "ncloud_public_ip" "web_ip" {
  server_instance_no = ncloud_server.web.instance_no
}
```

## Remediated example
```hcl
resource "ncloud_server" "web" {
  name                     = "web-server"
  server_image_product_code = "SW.VSVR.OS.LNX64.CNTOS.0708.B050"
}

# No public IP is associated with the server instance.
# Traffic is instead routed through a load balancer / NAT gateway.
resource "ncloud_lb" "web_lb" {
  name           = "web-lb"
  network_type   = "PUBLIC"
}
```

## Remediation steps
1. Remove the `server_instance_no` argument from the `ncloud_public_ip` resource (or delete the resource entirely) so the instance stays on a private-only network path.
2. Front the instance with an `ncloud_lb` (load balancer) or NAT gateway to handle inbound/outbound internet traffic instead of a direct public IP.
3. For administrative access, use a bastion host or NCP's VPN/Direct Connect service rather than a public IP on the target server.
4. If a public IP is genuinely required (e.g., a bastion host itself), consider suppressing this check for that specific resource with a documented justification rather than disabling it globally.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/ServerPublicIP.py)
