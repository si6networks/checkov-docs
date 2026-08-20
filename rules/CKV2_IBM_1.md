# CKV2_IBM_1: Ensure load balancer for VPC is private (disable public access)

## Severity
**HIGH** (score: 7.2/10)

A publicly-typed VPC load balancer exposes backend application/service traffic directly to the internet, broadening the attack surface for services that may not be designed to face untrusted networks.

## Summary
This check ensures that an IBM Cloud VPC load balancer (`ibm_is_lb`) is configured with `type` set to `private` or `private_path`, rather than being publicly reachable.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `ibm_is_lb`

This is a graph-based check (Checkov "graph check", defined as JSON) evaluating a single attribute of the load balancer resource.

## Why it matters
A public IBM Cloud VPC load balancer is reachable from the internet, which is appropriate for genuinely public-facing services but is a significant risk when the load balancer is meant to front internal services, backend APIs, or administrative interfaces. Exposing internal load balancers publicly widens the attack surface: it allows unauthenticated network scanning, direct exploitation attempts against backend pool members, and potential exposure of internal APIs or management endpoints that were never designed to be internet-facing. Keeping the load balancer private forces all access through the organization's VPC, VPN, Direct Link, or Transit Gateway connectivity, which is a far more controlled and auditable network boundary.

## How Checkov evaluates this
The check requires the `ibm_is_lb` resource's `type` attribute to exist, and passes if that attribute equals (case-insensitively) either `private` or `private_path`. If `type` is missing, or set to `public`, the check **fails**.

## Non-compliant example
```hcl
resource "ibm_is_lb" "example" {
  name    = "example-lb"
  subnets = [ibm_is_subnet.example.id]
  type    = "public"
}
```

## Remediated example
```hcl
resource "ibm_is_lb" "example" {
  name    = "example-lb"
  subnets = [ibm_is_subnet.example.id]
  type    = "private"
}
```

## Remediation steps
1. Set `type = "private"` (or `"private_path"` if using IBM's Private Path service, which allows controlled cross-account private connectivity) on the `ibm_is_lb` resource.
2. Ensure clients that need to reach the load balancer have appropriate private network connectivity (same VPC, VPC peering, Transit Gateway, VPN, or Direct Link).
3. If public access is genuinely required for a subset of traffic, consider a dedicated public-facing load balancer with a WAF/security group in front, keeping internal load balancers private.
4. Changing `type` on an existing load balancer may require recreation — check the provider's behavior and plan for a maintenance window.
5. Review security groups and ACLs on the backend pool members as defense in depth, regardless of the load balancer's exposure.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ibm/IBM_LoadBalancerforVPCisPrivate.json
- IBM Cloud docs: https://cloud.ibm.com/docs/vpc?topic=vpc-nlb-vs-elb
