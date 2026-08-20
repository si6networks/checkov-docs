# CKV_NCP_1: Ensure HTTP HTTPS Target group defines Healthcheck

## Severity
**MEDIUM** (score: 4.0/10)

An HTTP/HTTPS target group without a configured health check can route traffic to unhealthy or unresponsive backends, which is primarily an availability concern rather than a confidentiality or integrity risk.

## Summary
This check ensures that Naver Cloud Platform (NCP) load-balancer target groups (`ncloud_lb_target_group`) using the `HTTP` or `HTTPS` protocol define an active health check with a URL path, so the load balancer can accurately detect and route around unhealthy backends.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ncloud_lb_target_group`
- **Check type:** resource-configuration check (Python)

## Why it matters
Without a defined health check (specifically a `url_path` for HTTP/HTTPS checks), the load balancer cannot verify that backend instances are actually serving traffic correctly — it may keep sending requests to a target that's crashed, deadlocked, out of memory, or returning application errors, resulting in failed requests being served to end users. From a reliability and availability standpoint this undermines the entire purpose of a load balancer: automatic failover. It's also a security-relevant control, because a stuck/compromised or misbehaving instance that isn't automatically drained from rotation can continue to serve malicious or corrupted responses to clients, or become disproportionately targeted since it's known to be always in the pool. Configuring a real, application-aware health check endpoint (not just a TCP-level check) lets the LB actively probe application health and pull unhealthy nodes out of service.

## How Checkov evaluates this
The check looks at the `protocol` attribute of the `ncloud_lb_target_group` resource:
- If `protocol` is **not** `HTTP` or `HTTPS`, the result is `UNKNOWN` (the check doesn't apply, e.g. for TCP target groups).
- If `protocol` is `HTTP` or `HTTPS`, Checkov requires a `health_check` block to be present, and specifically for the first `health_check` entry to have a non-empty `url_path` key.
  - If `health_check` is missing, or present but its `url_path` is not set, the check **FAILS**.
  - If `health_check[0].url_path` is set, the check **PASSES**.

## Non-compliant example
```hcl
resource "ncloud_lb_target_group" "web_tg" {
  name        = "web-target-group"
  port        = 443
  protocol    = "HTTPS"
  vpc_no      = ncloud_vpc.main.vpc_no
  # no health_check block defined
}
```

## Remediated example
```hcl
resource "ncloud_lb_target_group" "web_tg" {
  name     = "web-target-group"
  port     = 443
  protocol = "HTTPS"
  vpc_no   = ncloud_vpc.main.vpc_no

  health_check {
    protocol   = "HTTPS"
    http_method = "GET"
    port        = 443
    url_path    = "/healthz"
    cycle       = 30
    up_threshold   = 2
    down_threshold = 2
  }
}
```

## Remediation steps
1. Add a `health_check` block to every `ncloud_lb_target_group` resource using the `HTTP` or `HTTPS` protocol.
2. Set `url_path` to a real, lightweight application endpoint that reflects true service health (e.g. `/healthz`) rather than a static asset or the root `/` (which may return 200 even if core dependencies are down).
3. Tune `cycle`, `up_threshold`, and `down_threshold` to balance fast failure detection against false-positive flapping.
4. Make sure the health-check endpoint doesn't require authentication and returns a fast, cheap response so it doesn't itself become a load or availability liability.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/ncp/LBTargetGroupDefinesHealthCheck.py)
- [Naver Cloud Terraform provider: ncloud_lb_target_group](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/lb_target_group)
