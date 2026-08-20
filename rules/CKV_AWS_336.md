# CKV_AWS_336: Ensure ECS containers are limited to read-only access to root filesystems
## Severity
**LOW** (score: 2.0/10)

A writable root filesystem lets an attacker who compromises a container tamper with binaries, install persistence, or stage further attack tooling, whereas a read-only filesystem substantially limits post-exploitation impact even though it isn't the initial attack vector.

## Summary
This check requires that every container definition in an `aws_ecs_task_definition` sets `readonlyRootFilesystem: true`, so the container's root filesystem cannot be written to at runtime.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_ecs_task_definition` (inspects the `container_definitions` JSON)

## Why it matters
A writable container root filesystem gives an attacker who achieves code execution inside the container a place to persist tools, drop malware/webshells, modify application binaries or configuration files, or tamper with logs to cover their tracks — all without needing any additional privilege escalation. Making the root filesystem read-only is a foundational container-hardening control: it doesn't prevent an initial compromise, but it substantially limits what an attacker can do afterward (no persistence within the running container, no ability to modify the application code they're exploiting), and it forces any legitimate need for writable storage (temp files, logs, caches) to go through explicitly declared, narrowly-scoped writable volumes/mount points instead of an unrestricted filesystem.

## How Checkov evaluates this
The check (`ECSContainerReadOnlyRoot.py`) parses `container_definitions`:
- If the container definitions list is empty, returns `UNKNOWN`.
- For each container in the list, if `container.get("readonlyRootFilesystem")` is falsy (missing, `false`, `null`), the check **FAILS**.
- Only if every container explicitly sets `readonlyRootFilesystem` to a truthy value does the check **PASS**.
- If `container_definitions` can't be found/parsed, returns `UNKNOWN`.

## Non-compliant example
```hcl
resource "aws_ecs_task_definition" "bad_example" {
  family                   = "app"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      name   = "app"
      image  = "app:latest"
      memory = 512
      # readonlyRootFilesystem not set -> writable root filesystem
    }
  ])
}
```

## Remediated example
```hcl
resource "aws_ecs_task_definition" "good_example" {
  family                   = "app"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      name                   = "app"
      image                  = "app:latest"
      memory                 = 512
      readonlyRootFilesystem = true

      mountPoints = [
        {
          sourceVolume  = "tmp"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]
    }
  ])

  volume {
    name = "tmp"
  }
}
```

## Remediation steps
1. Set `"readonlyRootFilesystem": true` on every container definition in the task.
2. Identify any paths the application legitimately needs to write to (temp directories, cache, logs) and provide them as explicit writable volumes/`mountPoints` (e.g., an EFS volume, a Docker `tmpfs`, or an ephemeral bind mount) rather than making the whole filesystem writable.
3. Test the application thoroughly after this change — apps that write to unexpected paths (default log locations, package manager caches, etc.) will fail startup or throw runtime errors until those paths are redirected to a writable mount.
4. Combine with a non-root container user and dropped Linux capabilities for defense in depth.
5. Task definitions are immutable; deploy the fix as a new task definition revision via a normal rolling service update.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSContainerReadOnlyRoot.py)
- [AWS: Task definition parameters — readonlyRootFilesystem](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html)
