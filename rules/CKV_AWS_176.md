# CKV_AWS_176: Ensure Logging is enabled for WAF Web Access Control Lists

## Severity
**LOW** (score: 2.0/10)

Disabled WAF logging removes visibility into blocked/allowed requests, hampering detection and investigation of attacks against the protected application, but does not itself create a new access path.

## Summary
This check requires that an AWS WAF Web ACL (classic WAF or WAF Regional) has a logging configuration with a log destination configured, so that requests inspected/matched by WAF rules are recorded for visibility and forensics.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_waf_web_acl`, `aws_wafregional_web_acl`

## Why it matters
Without WAF logging enabled, there is no record of which requests were inspected, which rules matched, or what action (allow/block/count) was taken — this creates a significant blind spot during incident response. If an application is compromised or an attacker probes for vulnerabilities, WAF logs are often the primary source for reconstructing the attack timeline (source IPs, payloads, matched rule IDs, targeted URIs). Without logging, security teams cannot retroactively investigate whether an attack was blocked, allowed through, or attempted at all, and cannot tune WAF rules based on real traffic patterns (e.g. identifying false positives blocking legitimate users, or new attack patterns not yet covered by existing rules).

Logging is also frequently a compliance requirement (PCI-DSS, SOC 2) for internet-facing web application firewalls, since auditors expect evidence that security controls are not just configured but actively monitored.

## How Checkov evaluates this
The check inspects `logging_configuration[0].log_destination` on `aws_waf_web_acl` / `aws_wafregional_web_acl`. It **PASSES** if this key is present with any non-empty value (`ANY_VALUE` sentinel — it does not validate that the destination is a *specific* correctly-configured Kinesis Firehose ARN, only that some value is set). If `logging_configuration` or `log_destination` is absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_wafregional_web_acl" "main" {
  name        = "app-waf"
  metric_name = "appWaf"

  default_action {
    type = "ALLOW"
  }
  # No logging_configuration block -> no visibility into matched requests
}
```

## Remediated example
```hcl
resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "aws-waf-logs-app-waf"  # must be prefixed "aws-waf-logs-"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn
  }
}

resource "aws_wafregional_web_acl" "main" {
  name        = "app-waf"
  metric_name = "appWaf"

  default_action {
    type = "ALLOW"
  }
}

resource "aws_wafregional_web_acl_logging_configuration" "main" {  # added
  resource_arn   = aws_wafregional_web_acl.main.arn
  log_destination = aws_kinesis_firehose_delivery_stream.waf_logs.arn
}
```

## Remediation steps
1. Create a Kinesis Data Firehose delivery stream named with the required `aws-waf-logs-` prefix, delivering to S3 (or another supported destination).
2. Attach a logging configuration to the Web ACL — for classic/regional WAF this is via `aws_wafregional_web_acl_logging_configuration` (or the inline `logging_configuration` block, depending on provider version) referencing the Firehose stream ARN as `log_destination`.
3. For WAFv2 (`aws_wafv2_web_acl`), use the separate `aws_wafv2_web_acl_logging_configuration` resource — note this specific Checkov check only covers classic/regional resource types, so WAFv2 ACLs should be verified for logging via a different mechanism/check.
4. Consider adding redaction rules for sensitive fields (e.g. `Authorization` headers, cookies) in the logging configuration to avoid capturing credentials/PII in WAF logs.
5. Route the logs to a SIEM or long-term storage with appropriate retention and access controls, since WAF logs themselves can contain sensitive request data.
6. This is an additive, non-disruptive change — it does not affect existing WAF rule evaluation or traffic handling.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/WAFHasLogs.py
- AWS docs: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
