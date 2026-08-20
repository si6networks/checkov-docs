# CKV_TC_2: Ensure Tencent Cloud CVM instance does not allocate a public IP

## Severity
**HIGH** (score: 7.5/10)

Assigning a public IP directly to a compute instance exposes every open port and running service on that instance to internet-wide scanning and brute-force attempts, bypassing the intended private-subnet perimeter.

## Summary
This check ensures that Tencent Cloud CVM (Cloud Virtual Machine) instances are not directly assigned a public IP address.

## Applicability
Terraform, resource type `tencentcloud_instance` (Tencent Cloud provider).

## Why it matters
Assigning a public IP directly to a compute instance exposes it to the entire internet, dramatically increasing its attack surface: any open port, unpatched service, or misconfigured firewall rule on the instance becomes reachable by anonymous scanners and attackers worldwide. Public-facing instances are frequent targets for credential brute-forcing (SSH/RDP), exploitation of known service vulnerabilities, and inclusion in automated botnet scanning within minutes of being provisioned. The recommended pattern is to keep compute instances on private subnets and route any required external access through a load balancer, bastion host, or NAT gateway, which centralizes exposure and access control at a single, hardened chokepoint rather than distributing it across every instance.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the `allocate_public_ip` attribute of a `tencentcloud_instance` resource. `true` is a forbidden value: if `allocate_public_ip` is set to `true`, the check **FAILS**. If the attribute is unset or explicitly `false`, the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_instance" "web" {
  instance_name     = "web-server"
  availability_zone = "ap-guangzhou-3"
  image_id          = "img-9qabwvbn"
  instance_type     = "S5.MEDIUM4"
  allocate_public_ip = true
}
```

## Remediated example
```hcl
resource "tencentcloud_instance" "web" {
  instance_name      = "web-server"
  availability_zone  = "ap-guangzhou-3"
  image_id           = "img-9qabwvbn"
  instance_type      = "S5.MEDIUM4"
  allocate_public_ip = false   # no direct public IP; expose via CLB/bastion instead
}
```

## Remediation steps
1. Set `allocate_public_ip = false` (or remove the attribute, since it defaults to false) on every `tencentcloud_instance`.
2. Place the instance in a private VPC subnet and route inbound traffic through a Tencent Cloud CLB (Cloud Load Balancer) for public-facing services.
3. For administrative access, use a bastion host / jump server, VPN, or Tencent Cloud's Cloud Connect Network rather than a direct public IP.
4. If a public IP is genuinely required (e.g. a NAT gateway or bastion itself), scope this resource narrowly and apply strict security-group rules limiting source IPs and ports.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CVMAllocatePublicIp.py
