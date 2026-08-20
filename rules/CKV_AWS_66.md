# CKV_AWS_66: Ensure that CloudWatch Log Group specifies retention days
## Severity
**LOW** (score: 2.0/10)

A CloudWatch Log Group without a retention policy keeps logs indefinitely (needless data retention/cost risk) or, if misconfigured, may be manually deleted, weakening the availability of audit trails needed for incident investigation.

## Summary
This check verifies that a CloudWatch Log Group has an explicit `RetentionInDays`/`retention_in_days` value set (any value), rather than defaulting to "Never Expire," so that log storage cost and data-retention policy are deliberately controlled.

## Applicability
- **CloudFormation**: `AWS::Logs::LogGroup`, property `Properties/RetentionInDays`.
- **Terraform**: `aws_cloudwatch_log_group` resource, attribute `retention_in_days`.

## Why it matters
By default, CloudWatch Log Groups retain log events indefinitely ("Never Expire") unless a retention period is explicitly configured. This has two concrete consequences: (1) unbounded, ever-growing storage costs as logs accumulate over the lifetime of the account/application, and (2) a data-governance/compliance risk — many regulatory frameworks (GDPR, HIPAA, PCI-DSS, internal data-retention policies) require that logs, which can contain PII or other sensitive data logged incidentally by applications, be retained only for a defined period and then deleted. Indefinite retention also increases the blast radius of a log-access compromise, since an attacker gaining read access to logs can retrieve the entire historical record rather than a bounded recent window. Explicitly setting retention (whether 30 days, 1 year, or otherwise per your policy) forces a deliberate decision rather than accidental indefinite accumulation.

## How Checkov evaluates this
Both are `BaseResourceValueCheck` implementations using `ANY_VALUE` as the expected value (meaning any concrete, non-empty value satisfies the check, not a specific number):
- **CloudFormation**: inspects `Properties/RetentionInDays`.
- **Terraform**: inspects `retention_in_days`.
- PASS: the attribute is present and set to any value (e.g., `7`, `30`, `365`, `0` would still count as "present" though `0` is not a valid AWS value in practice).
- FAIL: the attribute is absent entirely (implying indefinite/"Never Expire" retention).

Checkov does not enforce any specific retention duration — it only flags the complete absence of a retention setting.

## Non-compliant example
```hcl
resource "aws_cloudwatch_log_group" "app" {
  name = "/ecs/app"
  # retention_in_days not set -> logs retained forever
}
```

## Remediated example
```hcl
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/app"
  retention_in_days = 90            # fixed: explicit retention policy
}
```

## Remediation steps
1. Set `retention_in_days` (Terraform) or `RetentionInDays` (CloudFormation) to a value consistent with your organization's log-retention policy. Valid AWS values include 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653, and 0 (0 means never expire and is a valid literal but likely not what you want for compliance).
2. For log groups auto-created by AWS services (e.g., Lambda's default `/aws/lambda/<function>` group) that Terraform doesn't manage directly, create the `aws_cloudwatch_log_group` resource explicitly ahead of time with the desired retention rather than letting AWS auto-create it with no retention.
3. For long-lived audit/compliance logs, consider exporting to S3 with lifecycle policies for cheaper long-term archival instead of relying solely on CloudWatch Logs retention.
4. This is a non-disruptive, in-place change and does not require resource replacement.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/CloudWatchLogGroupRetention.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudWatchLogGroupRetention.py)
- [AWS: Change log data retention in CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html)
