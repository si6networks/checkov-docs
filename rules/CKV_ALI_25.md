# CKV_ALI_25: Ensure RDS Instance SQL Collector Retention Period should be greater than 180
## Severity
**LOW** (score: 2.0/10)

A short (or disabled) SQL Collector retention period limits the historical audit trail available for RDS activity, hampering incident investigation and detection of abuse rather than directly enabling an attack.

## Summary
This check verifies that the SQL Collector (SQL audit log) feature is enabled on Alibaba Cloud RDS instances and configured to retain logs for at least 180 days.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_db_instance`

## Why it matters
The SQL Collector captures a detailed audit trail of SQL statements executed against the database — who ran what query, when, and from where. This log is essential for forensic investigation after a suspected breach or data-integrity incident, for detecting anomalous or malicious query patterns (e.g. bulk data exfiltration via `SELECT *` dumps), and for demonstrating compliance with regulatory retention requirements. A short or disabled retention window means evidence needed to investigate an incident discovered weeks or months after it occurred may already have been purged, permanently losing visibility into what happened.

## How Checkov evaluates this
Custom `scan_resource_conf` logic on `alicloud_db_instance`:
1. Reads `sql_collector_status`. If it's present and not exactly `"Enabled"`, the check FAILS immediately.
2. If enabled, reads `sql_collector_config_value` (the retention period in days). PASSES only if this value is `>= 180`.
3. If `sql_collector_status` is absent, or `sql_collector_config_value` is absent/not a list, the check falls through to FAIL — the SQL Collector must be explicitly configured and enabled with an adequate retention period, not merely left at defaults.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine                     = "MySQL"
  engine_version             = "8.0"
  instance_type              = "rds.mysql.s1.small"
  instance_storage            = "20"
  vswitch_id                  = "vsw-example"
  sql_collector_status        = "Enabled"
  sql_collector_config_value  = 30   # <-- fails: retention below 180 days
}
```

## Remediated example
```hcl
resource "alicloud_db_instance" "example" {
  engine                     = "MySQL"
  engine_version             = "8.0"
  instance_type              = "rds.mysql.s1.small"
  instance_storage            = "20"
  vswitch_id                  = "vsw-example"
  sql_collector_status        = "Enabled"
  sql_collector_config_value  = 180  # <-- fix: retention meets or exceeds 180 days
}
```

## Remediation steps
1. Add or update `sql_collector_status = "Enabled"` on the `alicloud_db_instance` resource.
2. Set `sql_collector_config_value` to `180` or greater (in days).
3. Confirm this feature is supported for your specific RDS engine/edition — SQL Collector availability and pricing (extra storage cost for retained logs) varies by engine and instance class; check current Alibaba Cloud RDS documentation.
4. Route SQL audit logs to a long-term store (e.g., Log Service/SLS) if you need retention beyond what the built-in collector offers, or for centralized SIEM ingestion.
5. This is generally an in-place configuration change with no instance downtime, but confirm in a test instance before applying to production.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSRetention.py)
- [Alibaba Cloud RDS instance resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance)
