# CKV_AWS_334: Ensure ECS containers should run as non-privileged
## Severity
**MEDIUM** (score: 5.0/10)

Running an ECS container in privileged mode grants it root-equivalent access to the host's devices and kernel, so a compromised container can break out of its isolation boundary and take over the underlying host.

## Summary
This check requires that no container definition in an `aws_ecs_task_definition` sets `privileged: true`, preventing ECS containers (on EC2 launch type) from running with elevated host-level access equivalent to root on the underlying instance.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_ecs_task_definition` (inspects the `container_definitions` JSON)

## Why it matters
Setting `privileged: true` on a Docker/ECS container gives it near-full access to the host: it can access all host devices, bypass most kernel namespace and cgroup isolation, load kernel modules, and generally interact with the underlying EC2 instance as if it were root on that host, not just root inside a sandboxed container. If an application in a privileged container is compromised (e.g., via a dependency vulnerability or injection attack), the attacker inherits host-level capabilities — enabling container breakout, lateral movement to other containers/tasks sharing the same instance, and potentially full compromise of the underlying EC2 host. Privileged mode is almost never required for typical application workloads; it's usually only needed for specialized tooling (e.g., certain CI runners, low-level network/storage agents) that should be isolated onto dedicated infrastructure rather than run alongside regular application containers.

## How Checkov evaluates this
The check (`ECSContainerPrivilege.py`) parses `container_definitions` (a JSON array, possibly Terraform-plan-shaped as a dict):
- For each container in the list, if `container.get("privilege")` is truthy, the check **FAILS** for that resource. *(Note: the actual ECS task definition JSON field is `privileged`; the check as written inspects a key literally named `"privilege"` — see the Remediation caveat below.)*
- If none of the containers set that flag, the check **PASSES**.
- If `container_definitions` can't be parsed/found, the result is `UNKNOWN`.

## Non-compliant example
```hcl
resource "aws_ecs_task_definition" "bad_example" {
  family                   = "app"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"

  container_definitions = jsonencode([
    {
      name      = "app"
      image     = "app:latest"
      privileged = true
      memory    = 512
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

  container_definitions = jsonencode([
    {
      name       = "app"
      image      = "app:latest"
      privileged = false
      memory     = 512
    }
  ])
}
```

## Remediation steps
1. Remove `"privileged": true` from every container definition, or set it explicitly to `false`.
2. If a workload genuinely requires elevated host access (e.g., a specific device or kernel capability), grant only the specific Linux capability needed via `linuxParameters.capabilities.add` instead of full privileged mode — this follows least privilege far more closely.
3. If privileged access is unavoidable for a specialized workload, isolate it onto dedicated ECS container instances (via placement constraints) rather than sharing hosts with regular application tasks.
4. Note: `privileged` mode only applies to the EC2 launch type — Fargate does not support privileged containers at all, so migrating to Fargate is itself a strong mitigation where feasible.
5. Task definitions are immutable once created; changing this requires registering a new task definition revision and updating the service to use it (a standard rolling deployment, not a destructive replacement).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSContainerPrivilege.py)
- [AWS: Task definition parameters — privileged](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html)
