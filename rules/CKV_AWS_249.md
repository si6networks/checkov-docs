# CKV_AWS_249: Ensure that the Execution Role ARN and the Task Role ARN are different in ECS Task definitions

## Severity
**LOW** (score: 2.0/10)

Reusing the same role for both ECS execution and task roles hands application code (and any injected/compromised payload) the execution role's broader permissions such as ECR pulls and Secrets Manager/KMS decrypt access, violating least privilege and enlarging the blast radius of a code-level compromise.

## Summary
This check ensures that an ECS task definition uses distinct IAM roles for its `execution_role_arn` (used by the ECS agent to pull images/write logs) and `task_role_arn` (used by the running application code), rather than reusing the same role for both purposes.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_ecs_task_definition`

## Why it matters
ECS deliberately separates two distinct trust boundaries: the **execution role** is used by the ECS agent/container runtime itself (to pull images from ECR, decrypt Secrets Manager/SSM values referenced in the task definition, and write logs to CloudWatch) and is never exposed to the running application. The **task role** is assumed by your application code inside the container and is reachable by anything running there, including third-party dependencies or, in a compromise scenario, an attacker's payload. If the same role is used for both, then the application code inherits every permission the execution role needed — such as `ecr:GetAuthorizationToken`, `secretsmanager:GetSecretValue` for *other* secrets referenced in the task definition, or `kms:Decrypt` for the CMK used to encrypt those secrets — dramatically over-privileging the container process beyond what the application itself needs. This violates least-privilege and turns any code-execution vulnerability in the application into a much larger blast radius (e.g., pulling private images, reading unrelated secrets).

## How Checkov evaluates this
The check (`BaseResourceCheck.scan_resource_conf`) runs custom logic:

1. It only evaluates resources where **both** `execution_role_arn` and `task_role_arn` are present in the configuration.
2. If `execution_role_arn` is empty/`[None]` (common in rendered Terraform plan output when no role was set), it treats this as a pass (can't be evaluated meaningfully).
3. **FAIL**: if `conf["execution_role_arn"] == conf["task_role_arn"]` — i.e., the exact same value/reference is used for both.
4. **PASS**: otherwise (including when only one of the two attributes is set at all, since the check requires both keys to be present to compare).

## Non-compliant example
```hcl
resource "aws_iam_role" "shared" {
  name               = "ecs-shared-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_ecs_task_definition" "example" {
  family                   = "example-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.shared.arn
  task_role_arn       = aws_iam_role.shared.arn   # same role reused

  container_definitions = jsonencode([{
    name  = "app"
    image = "example/app:latest"
  }])
}
```

## Remediated example
```hcl
resource "aws_iam_role" "execution" {
  name               = "ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role" "task" {
  name               = "ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_ecs_task_definition" "example" {
  family                   = "example-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.execution.arn   # <-- separate role
  task_role_arn       = aws_iam_role.task.arn         # <-- separate role

  container_definitions = jsonencode([{
    name  = "app"
    image = "example/app:latest"
  }])
}
```

## Remediation steps
1. Create two distinct IAM roles: one for task execution (attach `AmazonECSTaskExecutionRolePolicy` plus any needed `secretsmanager:GetSecretValue`/`kms:Decrypt` for the specific secrets the *task definition* references), and one for the task itself (attach only the permissions the *application code* actually needs, e.g. `dynamodb:GetItem` on a specific table).
2. Assign the execution role to `execution_role_arn` and the task role to `task_role_arn`.
3. Audit each role's policy separately, removing any permission from the task role that's only needed for image pulls or definition-level secret injection.
4. Re-deploy the task definition (a new revision) — this does not require downtime as ECS services can roll forward to a new task definition revision.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSTaskDefinitionRoleCheck.py)
- [AWS: IAM roles for tasks](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
- [AWS: Task execution IAM role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html)
