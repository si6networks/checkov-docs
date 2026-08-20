# CKV_AWS_223: Ensure ECS Cluster enables logging of ECS Exec
## Severity
**LOW** (score: 2.0/10)

Disabling logging for ECS Exec removes the audit trail for interactive shell access into running containers, letting privileged debug sessions (including any malicious use of that access) go unrecorded.

## Summary
This check ensures that an ECS cluster (`aws_ecs_cluster`) has ECS Exec command logging enabled — i.e. the `execute_command_configuration.logging` setting is not `NONE` — so that interactive `ecs execute-command` sessions into running containers are logged.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_ecs_cluster`

## Why it matters
ECS Exec allows operators to open an interactive shell session directly into a running container, similar to `kubectl exec` or `docker exec`. This is a powerful capability with significant security implications: anyone with the right IAM permissions can run arbitrary commands inside production containers, potentially viewing or exfiltrating sensitive data, modifying running application state, or using the session as a foothold for further access. If logging is disabled (`logging = "NONE"`), these interactive sessions leave no audit trail — there is no record of who ran ECS Exec, when, against which task/container, or what commands were executed during the session. This creates a significant blind spot for incident response and forensics: a malicious or compromised IAM principal could use ECS Exec to tamper with or extract data from a container with no logged evidence of the activity.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the nested attribute path `configuration/[0]/execute_command_configuration/[0]/logging`:
- The forbidden value is `"NONE"`.
- If `logging` is set to `"NONE"`, the check **FAILS**.
- If `logging` is set to any other value (`"DEFAULT"` or `"OVERRIDE"`), the check **PASSES**.
- (Being a negative-value check, the exact missing-block behavior follows the base class's defaults — the key point is that an explicit `"NONE"` value is what triggers failure.)

## Non-compliant example
```hcl
resource "aws_ecs_cluster" "example" {
  name = "example-cluster"

  configuration {
    execute_command_configuration {
      logging = "NONE"
    }
  }
}
```

## Remediated example
```hcl
resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = "/ecs/example-cluster/exec-logs"
  retention_in_days = 90
}

resource "aws_ecs_cluster" "example" {
  name = "example-cluster"

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }
}
```

## Remediation steps
1. Set `execute_command_configuration.logging` to `"DEFAULT"` (uses the cluster's default CloudWatch logging configuration if already set up elsewhere) or `"OVERRIDE"` (explicitly specify a CloudWatch log group and/or S3 bucket destination for exec session logs).
2. If using `"OVERRIDE"`, add a `log_configuration` block specifying `cloud_watch_log_group_name` and/or `s3_bucket_name`.
3. Grant the ECS task execution role and any relevant service-linked permissions to write to the chosen CloudWatch log group / S3 bucket.
4. Consider also enabling encryption of the exec logs with a CMK (see CKV_AWS_224) for defense in depth.
5. Restrict IAM policies that grant `ecs:ExecuteCommand` to only the roles/users that genuinely need interactive container access, since logging is a detective control, not a preventive one.
6. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSClusterLoggingEnabled.py)
- [AWS ECS Exec: Logging and auditing](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html)
