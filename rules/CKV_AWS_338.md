# CKV_AWS_338: Ensure CloudWatch log groups retains logs for at least 1 year
## Severity
**LOW** (score: 2.0/10)

Insufficient CloudWatch log retention risks losing forensic and audit evidence needed to investigate incidents after the fact, an availability/completeness gap in the logging pipeline rather than a direct exposure of the environment.

## Summary
This check requires that `aws_cloudwatch_log_group` resources set `retention_in_days` to either `0` (never expire) or a value of `365` or more, ensuring logs are kept for at least a year.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_cloudwatch_log_group`

## Why it matters
CloudWatch Logs defaults to **never expiring** logs only if you don't set `retention_in_days` at all via the console, but in Terraform, if the attribute is omitted the provider also leaves retention unset (never expire) — however many teams explicitly set a short retention (e.g., 7, 14, or 30 days) to control storage costs, which can silently destroy evidence needed for incident response, forensic investigation, or compliance audits long after an event occurred. Security incidents (e.g., a credential compromise, an intrusion, or a data exfiltration attempt) are often not discovered until weeks or months after they happened; if application, VPC flow, or Lambda logs have already expired, the ability to reconstruct what happened is permanently lost. A minimum one-year retention window aligns with common compliance baselines (e.g., PCI DSS's one-year audit trail retention requirement) and gives incident responders a realistic window to detect and investigate delayed-discovery incidents.

## How Checkov evaluates this
The check (`CloudWatchLogGroupRetentionYear.py`):
- Inspects `retention_in_days`.
- If the value is not an integer (e.g., a variable reference that can't be resolved), returns `UNKNOWN`.
- If `retention_in_days == 0` (which in the AWS API/provider semantics represents "retain forever, never expire") **or** `retention_in_days >= 365`, the check **PASSES**.
- Any other explicit value below 365 (e.g., `7`, `30`, `90`, `180`) **FAILS**.
- If `retention_in_days` is not set at all, the check **FAILS** (note: this differs from the AWS console default of "never expire" — Checkov treats an unset attribute in Terraform as non-compliant since the intent isn't explicitly declared).

## Non-compliant example
```hcl
resource "aws_cloudwatch_log_group" "bad_example" {
  name              = "/ecs/app"
  retention_in_days = 30
}
```

## Remediated example
```hcl
resource "aws_cloudwatch_log_group" "good_example" {
  name              = "/ecs/app"
  retention_in_days = 365
}
```

## Remediation steps
1. Set `retention_in_days` to `365` or greater (common values: `365`, `400`, `545`, `731`), or `0` to retain logs indefinitely if your compliance/cost model supports that.
2. Factor in CloudWatch Logs storage costs when choosing a long retention period — consider exporting older logs to S3 with lifecycle rules (e.g., transition to Glacier) for cheaper long-term archival instead of keeping everything "hot" in CloudWatch indefinitely.
3. Audit all existing log groups across the account for short retention settings set for cost-saving reasons and reconcile them against your actual compliance/incident-response retention requirements.
4. This is a mutable attribute — changing `retention_in_days` applies immediately without recreating the log group, but it does not retroactively un-delete logs that already expired under a shorter policy.
5. Consider centralizing log retention policy via a Terraform module or AWS Config conformance pack so retention is enforced consistently rather than set ad hoc per log group.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudWatchLogGroupRetentionYear.py)
- [AWS: Change log data retention in CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html)
