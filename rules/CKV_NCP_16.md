# CKV_NCP_16: Ensure Load Balancer isn't exposed to the internet

## Severity
**HIGH** (score: 7.5/10)

A load balancer configured for public rather than private network type exposes the fronted service directly to the internet, broadening the attack surface for anything sitting behind it.

## Summary
This check ensures that Naver Cloud Platform (NCP) Load Balancer resources (`ncloud_lb`) are configured with `network_type = "PRIVATE"` rather than a public-facing network type.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ncloud_lb`
- **Check type:** resource-configuration attribute check

## Why it matters
A load balancer configured for public network access is directly reachable from the internet, meaning every backend service it fronts inherits internet exposure by default — anyone can attempt to connect, scan for open ports, fuzz the application, or launch (D)DoS traffic directly at it. For internal-only services (internal APIs, admin dashboards, service-to-service traffic, staging environments), there is no legitimate need for that exposure, and every public-facing endpoint is additional attack surface that must be patched, monitored, and defended. Keeping the load balancer private (only reachable from within the VPC or via a VPN/peering connection) removes an entire class of external attack vectors for workloads that were never meant to be internet-facing, while genuinely public services can still use a deliberately-provisioned public load balancer.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `network_type` attribute of the `ncloud_lb` resource, expecting the value `"PRIVATE"`. If `network_type` is set to `"PUBLIC"` (or any value other than `PRIVATE`), the check **FAILS**. If it is `"PRIVATE"`, the check **PASSES**.

## Non-compliant example
```hcl
resource "ncloud_lb" "internal_api_lb" {
  name          = "internal-api-lb"
  network_type  = "PUBLIC"
  type          = "APPLICATION"
  subnet_no_list = [ncloud_subnet.lb_subnet.id]
}
```

## Remediated example
```hcl
resource "ncloud_lb" "internal_api_lb" {
  name          = "internal-api-lb"
  network_type  = "PRIVATE"
  type          = "APPLICATION"
  subnet_no_list = [ncloud_subnet.lb_subnet.id]
}
```

## Remediation steps
1. Set `network_type = "PRIVATE"` on any `ncloud_lb` that fronts internal-only services.
2. Confirm that clients needing access reach the load balancer via VPC peering, a VPN gateway, or from instances already inside the same VPC.
3. For services that genuinely need to be public (e.g. a customer-facing website), keep a separate, deliberately provisioned public load balancer, and restrict what backends/ports it can reach rather than defaulting all load balancers to public.
4. Note that `network_type` is typically set at creation time — changing an existing public LB to private may require recreating the resource, so plan for a migration/cutover window and DNS updates.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/LBNetworkPrivate.py)
- [Naver Cloud Terraform provider: ncloud_lb](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/lb)
