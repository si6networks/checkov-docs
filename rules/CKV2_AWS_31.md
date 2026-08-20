# CKV2_AWS_31: Ensure WAF2 has a Logging Configuration
## Severity
**LOW** (score: 2.0/10)

A WAFv2 Web ACL without logging configured undermines the ability to investigate blocked/allowed requests and tune rules after an attack, weakening incident response rather than the WAF's blocking function itself.

## Summary
This check ensures that every `aws_wafv2_web_acl` has a connected `aws_wafv2_web_acl_logging_configuration`, so that the requests WAF inspects and the actions it takes are actually logged.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_wafv2_web_acl` (connected `aws_wafv2_web_acl_logging_configuration`)
- **Check type:** Graph-based connection check

## Why it matters
A WAF web ACL without logging enabled is a security control operating in the dark: it may be blocking, allowing, or counting requests, but with no logging configuration there is no record of which requests matched which rules, which IPs were blocked, or whether a rule is misconfigured and either blocking legitimate traffic (false positives causing availability issues) or failing to block attacks (false negatives). Logging is essential for tuning WAF rules over time (e.g., moving rules from "count" to "block" mode safely), for forensic investigation after a suspected attack, and for demonstrating compliance that layer-7 protections are active and effective. Without logs, security teams cannot validate that the WAF is doing what it's supposed to, and incident responders lose critical evidence of attempted exploitation against public-facing applications.

## How Checkov evaluates this
This is a graph check (`WAF2HasLogs.json`). It filters for resources of type `aws_wafv2_web_acl`, and passes only if a graph connection exists between that web ACL and an `aws_wafv2_web_acl_logging_configuration` resource (i.e., the logging configuration's `resource_arn` argument references the web ACL). Any `aws_wafv2_web_acl` with no corresponding logging configuration resource in the Terraform configuration fails.

## Non-compliant example
```hcl
resource "aws_wafv2_web_acl" "app_waf" {
  name  = "app-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "app-waf"
    sampled_requests_enabled   = true
  }
}
# No aws_wafv2_web_acl_logging_configuration for this web ACL
```

## Remediated example
```hcl
resource "aws_wafv2_web_acl" "app_waf" {
  name  = "app-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "app-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-app-waf"
  retention_in_days = 90
}

# The logging configuration satisfies the check
resource "aws_wafv2_web_acl_logging_configuration" "app_waf_logging" {
  resource_arn            = aws_wafv2_web_acl.app_waf.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]
}
```

## Remediation steps
1. Create a log destination — a CloudWatch Logs log group (name must be prefixed `aws-waf-logs-`), a Kinesis Data Firehose delivery stream, or an S3 bucket.
2. Add an `aws_wafv2_web_acl_logging_configuration` resource with `resource_arn` set to the web ACL's ARN and `log_destination_configs` pointing at the destination(s).
3. Optionally add `redacted_fields` in the logging configuration to redact sensitive headers (e.g., `Authorization`, cookies) from logged request data to avoid storing credentials/PII in logs.
4. Confirm IAM/resource policies on the destination (e.g., CloudWatch Logs resource policy) permit the WAF service to write logs — AWS requires specific permissions/naming conventions (e.g., the `aws-waf-logs-` prefix for CloudWatch log groups) for this to succeed.
5. Set an appropriate retention period on the log destination to balance forensic needs against storage cost.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/WAF2HasLogs.json)
- [AWS WAF logging documentation](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html)
