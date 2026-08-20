# CKV2_AWS_11: Ensure VPC flow logging is enabled in all VPCs

## Severity
**LOW** (score: 2.0/10)

Missing VPC flow logs removes visibility into network traffic patterns, significantly impeding detection of exfiltration, lateral movement, or reconnaissance within the VPC.

## Summary
This check ensures that every VPC has an associated VPC Flow Log capturing network traffic metadata.

## Applicability
**Checkov framework(s):** `terraform`

Terraform (AWS provider). Applies to `aws_vpc` resources, evaluated in connection with `aws_flow_log` resources.

## Why it matters
VPC Flow Logs record accepted and rejected traffic (source/destination IP, port, protocol, byte counts, action) at the ENI/subnet/VPC level. Without them, there is no network-layer audit trail to investigate incidents such as data exfiltration, port scanning, lateral movement, or unexpected outbound connections to malicious IPs. Flow logs are foundational for both proactive detection (feeding GuardDuty, SIEM correlation, anomaly detection) and after-the-fact forensics ("what did this compromised instance talk to, and when?"). Their absence is explicitly called out in the CIS AWS Foundations Benchmark and is one of the first gaps auditors and incident responders look for.

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_vpc` resources and requires a connection to exist between the `aws_vpc` and an `aws_flow_log` resource. If no `aws_flow_log` references the VPC (via its `vpc_id`), the check **FAILS**. If at least one flow log is attached, it **PASSES** — the check does not further validate the flow log's destination, traffic type, or retention settings.

## Non-compliant example
```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  # No aws_flow_log resource references this VPC
}
```

## Remediated example
```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/main-flow-logs"
  retention_in_days = 365
}

resource "aws_iam_role" "flow_log_role" {
  name               = "vpc-flow-log-role"
  assume_role_policy = data.aws_iam_policy_document.flow_log_assume.json
}

resource "aws_flow_log" "main" {                       # <-- fixed: flow log attached
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}
```

## Remediation steps
1. Add an `aws_flow_log` resource with `vpc_id` set to the VPC's ID for every VPC.
2. Choose a `traffic_type` of `ALL` (recommended for security visibility) rather than only `ACCEPT` or `REJECT`.
3. Send logs to either CloudWatch Logs (needs an IAM role granting `logs:CreateLogStream`/`PutLogEvents`) or S3 (`log_destination_type = "s3"`), depending on your analysis tooling.
4. Set a sensible retention period and, if using S3, a lifecycle policy to control storage cost.
5. Feed flow logs into GuardDuty (enabled by default once flow logs exist) or a SIEM for automated anomaly detection.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/VPCHasFlowLog.json
