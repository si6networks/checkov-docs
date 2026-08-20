# CKV_AWS_335: Ensure ECS task definitions should not share the host's process namespace
## Severity
**MEDIUM** (score: 5.0/10)

Sharing the host's PID namespace lets a container see and potentially signal or interact with processes running on the host and in sibling containers, undermining container isolation and aiding host-level compromise after a container is exploited.

## Summary
This check requires that no container definition in an `aws_ecs_task_definition` sets `pidMode` (task-level `pid_mode`) to `"host"`, preventing ECS tasks from sharing the underlying EC2 host's process namespace.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_ecs_task_definition` (inspects the `container_definitions` JSON for a `pidMode` field)

## Why it matters
When a task definition's process namespace mode is set to `host`, containers in that task can see and interact with **every process running on the host EC2 instance** — not just processes within their own task, but those belonging to any other task or system process scheduled on the same instance. This breaks the process isolation that containers are supposed to provide: a compromised or malicious container could enumerate other tasks' processes, potentially read process memory or `/proc` filesystem entries containing secrets/environment variables of unrelated workloads, send signals to (e.g., kill) other tasks' processes, or use process visibility to aid further host-level attacks. Since multiple unrelated application tasks are frequently co-located on the same ECS container instance (EC2 launch type with bridge/host networking), host PID mode significantly increases the blast radius of any single container compromise.

## How Checkov evaluates this
The check (`ECSContainerHostProcess.py`) parses `container_definitions`:
- For each container in the list, if `container.get("pidMode") == "host"`, the check **FAILS**.
- If none of the containers set `pidMode` to `host`, the check **PASSES**.
- If `container_definitions` is missing/unparseable, the result is `UNKNOWN`.

Note: `pidMode` (or `pid_mode` at the task-definition-level Terraform attribute) is actually a task-level setting in the real ECS API, not a per-container field — the check inspects for the literal key inside each container definition entry as represented in the parsed configuration.

## Non-compliant example
```hcl
resource "aws_ecs_task_definition" "bad_example" {
  family                   = "app"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  pid_mode                 = "host"

  container_definitions = jsonencode([
    {
      name   = "app"
      image  = "app:latest"
      memory = 512
    }
  ])
}
```

## Remediated example
```hcl
resource "aws_ecs_task_definition" "good_example" {
  family                   = "app"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  # pid_mode omitted -> each task gets its own isolated PID namespace

  container_definitions = jsonencode([
    {
      name   = "app"
      image  = "app:latest"
      memory = 512
    }
  ])
}
```

## Remediation steps
1. Remove `pid_mode = "host"` from the task definition (or explicitly set `pid_mode = "task"`, which shares the PID namespace only among containers within the same task — a much smaller, intentional blast radius — or leave it unset for full per-container isolation).
2. If host PID visibility is required for a legitimate monitoring/security agent, run that agent on dedicated container instances via placement constraints, not co-mingled with regular application tasks.
3. Fargate does not support `host` PID mode at all, so migrating workloads to Fargate removes this risk entirely where feasible.
4. Task definitions are immutable; apply the fix by registering a new revision and rolling the service over to it — no destructive replacement of running infrastructure is required beyond the normal deployment process.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSContainerHostProcess.py)
- [AWS: Task definition parameters — pidMode](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html)
