# CKV_AWS_328: Ensure that ALB is configured with defensive or strictest desync mitigation mode
## Severity
**HIGH** (score: 7.5/10)

Running an ALB/ELB in 'monitor' mode instead of defensive/strictest desync mitigation leaves the load balancer susceptible to HTTP request smuggling, which can be used to bypass security controls, poison caches, or hijack other users' requests.

## Summary
This check requires that Application/Classic Load Balancers (`aws_lb`, `aws_alb`, `aws_elb`) set `desync_mitigation_mode` to `defensive` or `strictest`, rather than the weaker `monitor` mode.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource types:** `aws_lb`, `aws_alb`, `aws_elb`

## Why it matters
HTTP desync (request smuggling) attacks exploit inconsistencies in how a front-end proxy (the load balancer) and back-end server parse ambiguous HTTP requests (e.g., conflicting `Content-Length`/`Transfer-Encoding` headers). An attacker can smuggle a second, hidden request inside one connection, causing the back end to process it as if it came from a different, subsequent client — enabling request hijacking, cache poisoning, session fixation, or bypassing front-end security controls (WAF rules, auth checks) entirely. AWS ELB/ALB's `desync_mitigation_mode` setting controls how strictly ambiguous requests are handled: `monitor` only logs anomalies without blocking anything, leaving the smuggling vector open; `defensive` (the AWS default) blocks the most dangerous patterns; `strictest` rejects any request with the slightest ambiguity, providing the strongest protection at the cost of occasionally rejecting legitimate-but-malformed traffic.

## How Checkov evaluates this
The check (`ALBDesyncMode.py`) extends `BaseResourceNegativeValueCheck`:
- It inspects `desync_mitigation_mode`.
- The forbidden value is `"monitor"` — if the attribute equals `monitor`, the check **FAILS**.
- Any other value (`defensive`, `strictest`), or omitting the attribute (which defaults to `defensive` at the AWS API level), **PASSES** (the negative-value-check base class treats a missing attribute as passing unless explicitly configured otherwise).

## Non-compliant example
```hcl
resource "aws_lb" "bad_example" {
  name               = "app-alb"
  load_balancer_type = "application"
  subnets            = var.subnet_ids

  desync_mitigation_mode = "monitor"
}
```

## Remediated example
```hcl
resource "aws_lb" "good_example" {
  name               = "app-alb"
  load_balancer_type = "application"
  subnets            = var.subnet_ids

  desync_mitigation_mode = "defensive"
}
```

## Remediation steps
1. Set `desync_mitigation_mode` to `"defensive"` (AWS's recommended default) or `"strictest"` for maximum protection.
2. If moving to `strictest`, test thoroughly in a staging environment first — it can reject requests from legacy clients or misbehaving upstream proxies that `defensive` mode tolerates.
3. Review ALB access logs / CloudWatch metrics after the change for unexpected `4xx` increases that might indicate legitimate traffic being blocked, and adjust back to `defensive` if needed.
4. This setting can be changed in place without replacing the load balancer.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ALBDesyncMode.py)
- [AWS: Desync mitigation mode](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#desync-mitigation-mode)
