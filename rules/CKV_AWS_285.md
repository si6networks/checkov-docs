# CKV_AWS_285: Ensure State Machine has execution history logging enabled
## Severity
**MEDIUM** (score: 5.0/10)

Without execution history logging, security-relevant state machine activity (inputs, transitions, errors) is not captured, hampering incident detection and forensic investigation of a genuinely security-relevant workflow.

## Summary
This check fails when an `aws_sfn_state_machine` resource's logging configuration does not include execution data (`include_execution_data = true`), meaning the detailed input/output/state data of executions is not being logged.

## Applicability
- **Framework:** Terraform
- **Resource:** `aws_sfn_state_machine`

## Why it matters
Step Functions execution history logging with `include_execution_data` enabled writes the full input and output payloads of each state transition to CloudWatch Logs, which is essential for auditing exactly what data flowed through a workflow, debugging why a specific execution took an unexpected branch, and forensically reconstructing what happened during a security incident (e.g., what data a compromised Lambda function received or returned within an orchestrated workflow). Without execution data in the logs, you can see *that* a state ran and *whether* it succeeded, but not *what data* was processed — a critical gap for incident response, compliance audit trails, and root-cause debugging of production issues. (Because payloads may be sensitive, teams should weigh this against data-minimization needs and consider log encryption/retention controls in tandem.)

## How Checkov evaluates this
The check uses `BaseResourceValueCheck` and inspects the attribute path `logging_configuration/[0]/include_execution_data` on `aws_sfn_state_machine`. It passes if that value is `true`, and fails if the `logging_configuration` block or the `include_execution_data` field is missing or `false`.

## Non-compliant example
```hcl
resource "aws_sfn_state_machine" "example" {
  name     = "example-state-machine"
  role_arn = aws_iam_role.sfn_role.arn
  definition = jsonencode({
    StartAt = "HelloWorld"
    States = {
      HelloWorld = { Type = "Pass", End = true }
    }
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = false
    level                   = "ALL"
  }
}
```

## Remediated example
```hcl
resource "aws_sfn_state_machine" "example" {
  name     = "example-state-machine"
  role_arn = aws_iam_role.sfn_role.arn
  definition = jsonencode({
    StartAt = "HelloWorld"
    States = {
      HelloWorld = { Type = "Pass", End = true }
    }
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                   = "ALL"
  }
}
```

## Remediation steps
1. Add or update the `logging_configuration` block on the `aws_sfn_state_machine` resource, setting `include_execution_data = true`.
2. Ensure a `log_destination` (CloudWatch Log Group ARN) is configured and `level` is set to an appropriate level (`ALL`, `ERROR`, or `FATAL`) — `include_execution_data` has no effect without a valid logging configuration.
3. Grant the state machine's IAM role permission to write to the target CloudWatch Log Group.
4. Because execution data logs may contain sensitive payloads, apply appropriate CloudWatch Logs encryption (KMS CMK), access controls, and retention policy to the destination log group.
5. This is an in-place change; no resource replacement or downtime is required.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/StateMachineLoggingExecutionHistory.py
- AWS docs: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html
