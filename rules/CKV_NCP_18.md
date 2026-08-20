# CKV_NCP_18: Ensure that auto Scaling groups that are associated with a load balancer, are using Load Balancing health checks

## Severity
**MEDIUM** (score: 4.0/10)

An Auto Scaling group that isn't wired to load-balancer health checks can keep unhealthy instances in rotation, which primarily threatens availability rather than confidentiality or integrity.

## Summary
This check ensures that a Naver Cloud Platform (NCP) Auto Scaling Group (`ncloud_auto_scaling_group`) connected to a load-balancer target group uses the load balancer's health-check results (`health_check_type_code = "LOADB"`) — with that target group itself defining a real health check — rather than only relying on basic server-level health checks that don't reflect application health.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `ncloud_auto_scaling_group`, `ncloud_lb_target_group`
- **Check type:** graph-based check (`.json` connection/attribute query)

## Why it matters
An Auto Scaling Group's health-check type determines how it decides an instance is unhealthy and needs to be terminated/replaced. `SVR` (server-level) health checks only detect whether the underlying VM is running — they cannot see whether the application inside is actually responding correctly (e.g. hung request queue, crashed application process, dependency outage causing 500s). If an ASG behind a load balancer uses only server-level checks, an instance can be "alive" at the OS level while completely failing to serve traffic — the ASG won't replace it, and the load balancer keeps routing traffic to a broken node, causing a persistent partial outage that autoscaling never resolves. Requiring `LOADB` health checks (health determined by the load balancer's own probes) ties instance replacement decisions to real application-level health, ensuring genuinely broken instances are actually cycled out.

## How Checkov evaluates this
This is a graph-based check defined in `AutoScalingEnabledLB.json`. It filters to `ncloud_auto_scaling_group` resources and passes if **either**:
- `health_check_type_code` equals `"SVR"` (server-level checks are acceptable on their own), **or**
- `health_check_type_code` equals `"LOADB"` **and** the ASG is connected to an `ncloud_lb_target_group` **and** that target group has a `health_check` attribute defined.

If the ASG specifies `LOADB` but is not actually connected to a target group with a defined `health_check`, the check **FAILS** — because the ASG claims to rely on load-balancer health but there's no real health check backing that decision.

## Non-compliant example
```hcl
resource "ncloud_auto_scaling_group" "app_asg" {
  name                    = "app-asg"
  launch_configuration_no = ncloud_launch_configuration.app.id
  min_size                = 2
  max_size                = 6
  health_check_type_code  = "LOADB"
  target_group_list       = [ncloud_lb_target_group.app_tg.id]
}

resource "ncloud_lb_target_group" "app_tg" {
  name     = "app-target-group"
  port     = 443
  protocol = "HTTPS"
  vpc_no   = ncloud_vpc.main.vpc_no
  # no health_check block -> ASG's LOADB checks have nothing real to rely on
}
```

## Remediated example
```hcl
resource "ncloud_auto_scaling_group" "app_asg" {
  name                    = "app-asg"
  launch_configuration_no = ncloud_launch_configuration.app.id
  min_size                = 2
  max_size                = 6
  health_check_type_code  = "LOADB"
  target_group_list       = [ncloud_lb_target_group.app_tg.id]
}

resource "ncloud_lb_target_group" "app_tg" {
  name     = "app-target-group"
  port     = 443
  protocol = "HTTPS"
  vpc_no   = ncloud_vpc.main.vpc_no

  health_check {
    protocol    = "HTTPS"
    http_method = "GET"
    port        = 443
    url_path    = "/healthz"
  }
}
```

## Remediation steps
1. If `health_check_type_code = "LOADB"` on an `ncloud_auto_scaling_group`, ensure it references (via `target_group_list`) an `ncloud_lb_target_group` that defines a `health_check` block (see also `CKV_NCP_1`).
2. Alternatively, if a real application health check isn't feasible yet, set `health_check_type_code = "SVR"` as an interim, less-precise but still valid, compliant configuration.
3. Choose a meaningful `url_path` for the target group's health check that reflects true application readiness, not just process liveness.
4. Validate scaling behavior in a non-production environment — switching health-check types changes how aggressively unhealthy instances get replaced, which can affect availability during deploys.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ncp/AutoScalingEnabledLB.json)
- [Naver Cloud Terraform provider: ncloud_auto_scaling_group](https://registry.terraform.io/providers/NaverCloudPlatform/ncloud/latest/docs/resources/auto_scaling_group)
