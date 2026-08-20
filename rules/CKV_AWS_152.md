# CKV_AWS_152: Ensure that Load Balancer (Network/Gateway) has cross-zone load balancing enabled
## Severity
**LOW** (score: 2.0/10)

Cross-zone load balancing affects even distribution of traffic across availability zones, an availability/performance characteristic with no direct confidentiality or access-control impact.

## Summary
This check verifies that a Network or Gateway Load Balancer has `enable_cross_zone_load_balancing` set to `true`, so traffic is evenly distributed across targets in all enabled Availability Zones rather than only within the AZ that received the request.

## Applicability
Terraform only. Applies to `aws_lb` and `aws_alb` resources — but only when `load_balancer_type` is `network` or `gateway`. Application Load Balancers are exempted (cross-zone balancing is always on and non-configurable for ALBs).

## Why it matters
By default, an NLB/GWLB routes each incoming connection only to targets registered in the same Availability Zone that received the connection ("zonal" routing), not across all AZs. If target registration is uneven across AZs (e.g. an Auto Scaling group temporarily has more healthy instances in one AZ, or a whole AZ's targets become unhealthy), traffic gets unevenly distributed — some targets are overloaded, others idle — and in a worst case, an AZ with no healthy targets simply drops all traffic routed to it instead of failing over to healthy targets in another AZ. Enabling cross-zone load balancing spreads traffic evenly across every registered, healthy target in every enabled AZ, materially improving resilience during partial AZ failures and avoiding hot-spotting from imbalanced target counts.

## How Checkov evaluates this
Custom `scan_resource_conf`: if `load_balancer_type` is `"application"` (the default when unset), the check returns `UNKNOWN` (not applicable, since ALBs are always cross-zone). Otherwise it falls through to the base `BaseResourceValueCheck` logic on `enable_cross_zone_load_balancing`: `PASSED` if `true`, `FAILED` if `false` or unset (defaults to `false` for NLB/GWLB).

## Non-compliant example
```hcl
resource "aws_lb" "nlb" {
  name               = "app-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids
}
```

## Remediated example
```hcl
resource "aws_lb" "nlb" {
  name                             = "app-nlb"
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = var.private_subnet_ids
  enable_cross_zone_load_balancing = true # <-- added
}
```

## Remediation steps
1. For every `aws_lb`/`aws_alb` with `load_balancer_type = "network"` or `"gateway"`, add `enable_cross_zone_load_balancing = true`.
2. Be aware that enabling cross-zone load balancing for an NLB incurs inter-AZ data transfer charges for traffic that crosses AZ boundaries — factor this into cost estimates for high-throughput workloads.
3. Ensure target groups register instances across multiple AZs to actually benefit from the setting; cross-zone balancing with targets in a single AZ provides no resilience gain.
4. No action needed for `load_balancer_type = "application"` — Checkov reports `UNKNOWN`/not applicable since ALBs are always cross-zone.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LBCrossZone.py
- AWS docs: https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html#cross-zone-load-balancing
