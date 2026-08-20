# CKV_AWS_284: Ensure State Machine has X-Ray tracing enabled
## Severity
**LOW** (score: 2.0/10)

Missing X-Ray tracing on a Step Functions state machine reduces operational visibility and debugging capability but does not itself expose data or weaken access control.

## Summary
This check fails when an `aws_sfn_state_machine` (AWS Step Functions) resource does not have X-Ray tracing enabled, reducing visibility into execution behavior and making performance/error diagnosis harder.

## Applicability
- **Framework:** Terraform
- **Resource:** `aws_sfn_state_machine`

## Why it matters
AWS X-Ray tracing on a Step Functions state machine provides distributed tracing across every state transition and downstream service invocation (Lambda, ECS, SNS, etc.), capturing timing, error, and fault data for each step of a workflow. Without it, when a state machine execution fails, stalls, or behaves unexpectedly in production, engineers are left correlating CloudWatch Logs manually across every integrated service with no unified trace view — significantly slowing incident response (MTTR) and making it harder to detect where latency or errors originate in complex, multi-service workflows. This is primarily a reliability/observability control rather than a direct confidentiality control, but it materially affects an organization's ability to detect and respond to failures or anomalous execution patterns (including those caused by malicious input) in business-critical orchestrations.

## How Checkov evaluates this
The check uses `BaseResourceValueCheck` and inspects the attribute path `tracing_configuration/[0]/enabled` on `aws_sfn_state_machine`. It passes if that value is `true`, and fails if the `tracing_configuration` block (or its `enabled` field) is missing or `false`.

## Non-compliant example
```hcl
resource "aws_sfn_state_machine" "example" {
  name     = "example-state-machine"
  role_arn = aws_iam_role.sfn_role.arn
  definition = jsonencode({
    Comment = "An example state machine"
    StartAt = "HelloWorld"
    States = {
      HelloWorld = {
        Type = "Pass"
        End  = true
      }
    }
  })
  # tracing_configuration not set -> tracing disabled
}
```

## Remediated example
```hcl
resource "aws_sfn_state_machine" "example" {
  name     = "example-state-machine"
  role_arn = aws_iam_role.sfn_role.arn
  definition = jsonencode({
    Comment = "An example state machine"
    StartAt = "HelloWorld"
    States = {
      HelloWorld = {
        Type = "Pass"
        End  = true
      }
    }
  })

  tracing_configuration {
    enabled = true
  }
}
```

## Remediation steps
1. Add a `tracing_configuration { enabled = true }` block to the `aws_sfn_state_machine` resource.
2. Ensure the state machine's IAM role includes X-Ray write permissions (`xray:PutTraceSegments`, `xray:PutTelemetryRecords`, `xray:GetSamplingRules`, `xray:GetSamplingTargets`) — Terraform will not add these automatically.
3. This is an in-place, non-destructive update; no downtime or resource replacement is required.
4. Consider setting up X-Ray sampling rules to control trace volume/cost for high-throughput state machines, since every enabled execution incurs X-Ray trace segment costs.
5. Pair with CKV_AWS_285 (execution history logging) for full observability of both the trace path and the detailed execution log data.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/StateMachineXray.py
- AWS docs: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-xray-tracing.html
