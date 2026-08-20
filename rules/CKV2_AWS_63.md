# CKV2_AWS_63: Ensure Network firewall has logging configuration defined

## Severity
**LOW** (score: 2.0/10)

A network firewall without logging enabled loses visibility into blocked/allowed traffic, hampering detection and forensic response to genuine network-layer attacks, though it does not itself open an exposure.

## Summary
This check requires every `aws_networkfirewall_firewall` resource to have a connected `aws_networkfirewall_logging_configuration` resource, ensuring firewall traffic and alert events are actually logged.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_networkfirewall_firewall` (must be connected to `aws_networkfirewall_logging_configuration`)

## Why it matters
AWS Network Firewall enforces stateful and stateless rules at the VPC boundary, but without logging enabled, none of its decisions are recorded: dropped/blocked connections, matched alert rules, and flow-level metadata all disappear silently. This creates a significant detection and forensics gap — an ongoing scan, an exploit attempt blocked by a rule, or a data-exfiltration attempt caught by an egress rule produces no record to investigate, correlate with other signals (GuardDuty, VPC Flow Logs, SIEM), or use for incident response and compliance evidence. Enabling logging (to CloudWatch Logs, S3, or Kinesis Data Firehose) is what turns the firewall from a silent enforcement point into an observable control that feeds monitoring, alerting, and audit trails.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy):
1. Filters to resources of type `aws_networkfirewall_firewall`.
2. Requires a graph **connection** to an `aws_networkfirewall_logging_configuration` resource (which references the firewall via `firewall_arn`).

If no logging configuration resource references the firewall, the check **FAILS**. The check does not validate which specific log types (`ALERT` vs `FLOW`) are configured or where logs are shipped — only that a logging configuration exists and is wired to the firewall.

## Non-compliant example
```hcl
resource "aws_networkfirewall_firewall" "perimeter" {
  name                = "vpc-perimeter-fw"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.main.id

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }
}
# No aws_networkfirewall_logging_configuration -> FAILS
```

## Remediated example
```hcl
resource "aws_networkfirewall_firewall" "perimeter" {
  name                = "vpc-perimeter-fw"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.main.id

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }
}

resource "aws_cloudwatch_log_group" "fw_alerts" {
  name              = "/aws/networkfirewall/alerts"
  retention_in_days = 90
}

resource "aws_networkfirewall_logging_configuration" "perimeter" {
  firewall_arn = aws_networkfirewall_firewall.perimeter.arn

  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.fw_alerts.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type              = "ALERT"
    }
  }
}
```

## Remediation steps
1. Add an `aws_networkfirewall_logging_configuration` resource with `firewall_arn` referencing the firewall.
2. Configure at least one `log_destination_config` block for `log_type = "ALERT"` (rule matches) — add a second for `FLOW` (all traffic flow metadata) if full traffic visibility is required.
3. Choose a `log_destination_type` (`CloudWatchLogs`, `S3`, or `KinesisDataFirehose`) matching your existing log pipeline/SIEM ingestion path.
4. Set an appropriate retention period on the destination (e.g., CloudWatch Logs group retention) to balance cost against audit/investigation needs.
5. Ensure IAM permissions exist for Network Firewall to write to the chosen destination (service-linked role or resource policy, depending on destination type).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/NetworkFirewallHasLogging.json
- AWS docs: https://docs.aws.amazon.com/network-firewall/latest/developerguide/logging.html
