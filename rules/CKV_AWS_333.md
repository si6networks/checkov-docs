# CKV_AWS_333: Ensure ECS services do not have public IP addresses assigned to them automatically
## Severity
**LOW** (score: 2.0/10)

Automatically assigning public IP addresses to ECS tasks exposes the service's network interfaces directly to the internet, bypassing the intended layer of network isolation and enlarging the attack surface for services that should stay private.

## Summary
This check requires that `aws_ecs_service` resources using `awsvpc` networking do not set `network_configuration.assign_public_ip = true`, preventing tasks from automatically receiving a public IP address.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_ecs_service`

## Why it matters
When ECS tasks (particularly Fargate tasks using `awsvpc` networking mode) are launched with `assign_public_ip = true`, each task gets a public IPv4 address directly reachable from the internet, subject only to the security group rules attached to it. This flattens the intended network boundary between "internet-facing" and "internal" workloads: application containers that should only be reachable through a load balancer or from within the VPC become directly internet-addressable, increasing the attack surface for port scanning, direct exploitation attempts against the container's exposed ports, and credential-stuffing/DoS against application endpoints that were never meant to be public. The standard secure pattern is for tasks to live in private subnets (reaching the internet via a NAT gateway if outbound access is needed) and be fronted by a load balancer for inbound traffic, keeping task IPs private.

## How Checkov evaluates this
The check (`ECSServicePublicIP.py`) extends `BaseResourceNegativeValueCheck`:
- It inspects the nested key `network_configuration/[0]/assign_public_ip`.
- The forbidden value is `True` — if `assign_public_ip = true`, the check **FAILS**.
- If set to `false` or omitted (AWS defaults this to `false`), the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_ecs_service" "bad_example" {
  name            = "app-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = true
  }
}
```

## Remediated example
```hcl
resource "aws_ecs_service" "good_example" {
  name            = "app-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }
}
```

## Remediation steps
1. Set `assign_public_ip = false` (or remove the attribute).
2. Move the task's `subnets` to private subnets that route outbound traffic through a NAT gateway (if the container needs internet egress, e.g., to pull images or call external APIs).
3. Front the service with an Application Load Balancer or Network Load Balancer in public subnets for any inbound traffic that needs to come from the internet, rather than exposing the task directly.
4. Tighten the associated security group to only allow the necessary ports from the load balancer's security group or specific internal CIDRs, not `0.0.0.0/0`.
5. This is a service-level networking change; ECS will redeploy tasks with the new network configuration, causing a rolling replacement of running tasks (brief connection draining, no need to replace the service resource).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSServicePublicIP.py)
- [AWS: Task networking with the awsvpc network mode](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking.html)
