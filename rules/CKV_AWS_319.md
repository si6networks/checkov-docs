# CKV_AWS_319: Ensure that CloudWatch alarm actions are enabled

## Severity
**MEDIUM** (score: 5.0/10)

Disabled CloudWatch alarm actions mean configured alarms will not notify or trigger response actions, delaying detection of and response to operational or security-relevant threshold breaches.

## Summary
This check ensures CloudWatch metric alarms have `actions_enabled` set so that configured alarm actions (SNS notification, Auto Scaling action, etc.) actually fire when the alarm state changes.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_cloudwatch_metric_alarm`

## Why it matters
A CloudWatch alarm with `actions_enabled = false` will still evaluate its metric and transition between OK/ALARM/INSUFFICIENT_DATA states, but it will **not** invoke any of the actions attached to it (`alarm_actions`, `ok_actions`, `insufficient_data_actions`) — no SNS notification, no PagerDuty page, no Auto Scaling trigger, no Lambda invocation. This creates a dangerous false sense of security: the alarm exists in the console and appears "configured," dashboards may even show it firing, but nobody and nothing is actually notified or reacts. Security- and reliability-relevant alarms (unauthorized API calls, root account usage, GuardDuty findings forwarded via CloudWatch, resource exhaustion, failed logins) that are silently non-actionable defeat continuous monitoring entirely (NIST 800-53 CA-7, SI-4(12), AU-6(1)). This is often introduced accidentally — e.g., disabled temporarily during a maintenance window or testing and never re-enabled.

## How Checkov evaluates this
A `BaseResourceNegativeValueCheck` inspecting `actions_enabled`:
- **FAIL** if `actions_enabled` is explicitly set to `false`.
- **PASS** if it is `true`, or unset (Terraform/AWS default for `actions_enabled` is `true`).

## Non-compliant example
```hcl
resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "unauthorized-api-calls"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  actions_enabled     = false          # alarm state changes but nobody is notified
}
```

## Remediated example
```hcl
resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "unauthorized-api-calls"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  actions_enabled     = true           # or simply omit the argument (defaults to true)
}
```

## Remediation steps
1. Remove `actions_enabled = false` or set it to `true` on the alarm resource.
2. Verify `alarm_actions`, `ok_actions`, and `insufficient_data_actions` reference valid, monitored SNS topics or other action targets — an enabled alarm with no actions attached is equally ineffective.
3. Audit all alarms in the account for `actions_enabled = false` (a common leftover from maintenance windows) using `aws cloudwatch describe-alarms --query "MetricAlarms[?ActionsEnabled==\`false\`]"`.
4. Confirm the SNS topic (or other destination) has active, correct subscriptions (email, Slack integration, PagerDuty, etc.) — an alarm firing to an empty/unsubscribed topic is a similar silent-failure mode.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CloudWatchAlarmsEnabled.py
- AWS docs: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
