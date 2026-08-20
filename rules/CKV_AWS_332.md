# CKV_AWS_332: Ensure ECS Fargate services run on the latest Fargate platform version
## Severity
**MEDIUM** (score: 5.0/10)

Pinning an ECS Fargate service to an older platform version delays receipt of AWS-managed OS and runtime security patches, extending the window in which known vulnerabilities in the platform remain exploitable.

## Summary
This check requires that ECS services using the `FARGATE` launch type set `platform_version = "LATEST"`, ensuring tasks run on the most current Fargate runtime rather than being pinned to an older, potentially unpatched platform version.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_ecs_service`
- **Scope:** Only services with `launch_type = "FARGATE"` — EC2-launch-type services return `UNKNOWN` since platform version doesn't apply.

## Why it matters
AWS periodically releases new Fargate platform versions that include security patches, kernel updates, and updated container agent/runtime components underlying the managed compute environment. Pinning to a specific older platform version (or never updating it) means your workloads keep running on a runtime that may carry known, since-patched vulnerabilities in the underlying infrastructure AWS manages on your behalf — even though you don't manage the host OS yourself, you are still exposed to unpatched components until you explicitly upgrade the platform version. Since this is one of the few AWS-managed layers where you retain a version-selection choice, treating it like unpatched EC2 AMIs or container base images (i.e., keeping it current) is important for maintaining baseline platform security.

## How Checkov evaluates this
The check (`ECSServiceFargateLatest.py`):
1. If `launch_type` is not `"FARGATE"`, returns `UNKNOWN` (not applicable — EC2 launch type doesn't use `platform_version` the same way).
2. If `launch_type == "FARGATE"`: inspects `platform_version`. If it is set and **not equal to** `"LATEST"`, the check **FAILS**.
3. If `platform_version` is `"LATEST"` (or unset — Fargate defaults to `LATEST` when omitted, and the code path where `platform_version` is falsy returns PASSED), the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_ecs_service" "bad_example" {
  name            = "app-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  platform_version = "1.4.0"

  network_configuration {
    subnets = var.subnet_ids
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

  platform_version = "LATEST"

  network_configuration {
    subnets = var.subnet_ids
  }
}
```

## Remediation steps
1. Set `platform_version = "LATEST"` explicitly (or remove the attribute, since `LATEST` is the default when unset).
2. If you previously pinned a specific version to control rollout timing (e.g., avoiding a breaking change), instead adopt a deliberate upgrade process: track AWS's Fargate platform version release notes and update the pinned version on your own schedule rather than freezing indefinitely.
3. Test service behavior after moving to `LATEST` in a non-production environment first, since Fargate periodically deprecates older platform versions and behavior can shift subtly (e.g., ephemeral storage defaults, networking behavior).
4. This is a service-level attribute update; ECS will perform a rolling deployment of new tasks on the updated platform version without requiring you to replace the service resource itself.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSServiceFargateLatest.py)
- [AWS: AWS Fargate platform versions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html)
