# CKV_AWS_138: Ensure that ELB is cross-zone-load-balancing enabled

## Severity
**LOW** (score: 2.0/10)

Disabled cross-zone load balancing is an availability/traffic-distribution concern (uneven load across AZs) rather than a confidentiality or access-control weakness.

## Summary
This check requires Classic Load Balancers (`aws_elb`) to enable cross-zone load balancing, so incoming traffic is distributed evenly across all registered instances in all enabled Availability Zones rather than being confined to instances in the same AZ as the receiving load balancer node.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_elb` (Classic Load Balancer)

## Why it matters
Without cross-zone load balancing, each load balancer node only distributes traffic among the targets in its own Availability Zone. If instance counts are uneven across AZs (e.g., an Auto Scaling Group scales differently per AZ, or one AZ has fewer healthy instances due to a partial outage or a targeted infrastructure disruption), some instances end up carrying a disproportionate share of traffic while others sit idle. This uneven distribution can turn a partial-capacity event (e.g., an AZ losing some instances to a failure or attack) into a full-blown availability problem, as the surviving instances in the affected AZ get overwhelmed instead of load being smoothly absorbed by healthy capacity elsewhere. Enabling cross-zone balancing improves resilience and predictable behavior during AZ-level capacity imbalances or failures.

## How Checkov evaluates this
The check (`ELBCrossZoneEnable`, `BaseResourceValueCheck`) inspects the `cross_zone_load_balancing` attribute:
- **PASS** if `cross_zone_load_balancing = true`.
- **FAIL** if explicitly set to `false`.
- If the attribute is **missing entirely**, the check is configured with `missing_block_result=CheckResult.PASSED`, so an unset attribute **passes** (note: this differs from the AWS Classic ELB API default, which is actually `false` for cross-zone load balancing — Checkov's check gives the benefit of the doubt when the attribute is omitted, so developers should not rely on omission and should set the value explicitly).

## Non-compliant example
```hcl
resource "aws_elb" "app" {
  name               = "app-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 443
    lb_protocol       = "https"
    ssl_certificate_id = aws_acm_certificate.app.arn
  }

  cross_zone_load_balancing = false   # FAIL: explicitly disabled
}
```

## Remediated example
```hcl
resource "aws_elb" "app" {
  name               = "app-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 443
    lb_protocol       = "https"
    ssl_certificate_id = aws_acm_certificate.app.arn
  }

  cross_zone_load_balancing = true   # added / changed
}
```

## Remediation steps
1. Set `cross_zone_load_balancing = true` explicitly on the `aws_elb` resource — do not rely on the attribute's absence, since Checkov treats omission as passing but the actual AWS default behavior for Classic ELBs is disabled cross-zone balancing.
2. Ensure the ELB is registered with instances/targets across all the Availability Zones you expect it to balance over.
3. Consider migrating from the legacy Classic Load Balancer to an Application or Network Load Balancer (`aws_lb`), where cross-zone load balancing is enabled by default for ALBs and configurable for NLBs — this removes the need for this specific manual toggle.
4. This is a non-disruptive attribute update with no resource replacement required.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ELBCrossZoneEnable.py)
- [AWS: Configure cross-zone load balancing for your Classic Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html)
