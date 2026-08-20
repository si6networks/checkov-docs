# CKV_ALI_38: Ensure log audit is enabled for RDS
## Severity
**LOW** (score: 2.0/10)

Disabling RDS log audit removes centralized security logging for the database tier, a genuinely security-relevant monitoring control whose absence can let malicious activity go undetected.

## Summary
This check ensures that an Alibaba Cloud Log Service audit configuration (`alicloud_log_audit`) has RDS auditing enabled, so activity on RDS database instances is captured by the centralized log audit pipeline.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_log_audit`

## Why it matters
`alicloud_log_audit` is Alibaba Cloud's centralized, multi-service audit-log collection resource, which can ingest logs from services like OSS, ActionTrail, SLB, and RDS into a Log Service project for retention, querying, and alerting. If RDS auditing is not enabled within this resource, database-level activity (queries, connections, administrative actions) is excluded from the organization's centralized audit trail, creating a blind spot precisely where sensitive data typically resides. This undermines incident detection and forensic capability at the data layer, and can cause an organization to fail audit/compliance requirements that mandate centralized, tamper-evident logging of all data-store activity.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute path `variable_map/[0]/rds_enabled` on the `alicloud_log_audit` resource (the `variable_map` block holds toggles for which services are audited).
- **FAIL** if `variable_map[0].rds_enabled` is not present or not set to `true`.
- **PASS** only when `variable_map { rds_enabled = true }` (or equivalent, e.g. `"true"`) is explicitly set.

## Non-compliant example
```hcl
resource "alicloud_log_audit" "example" {
  display_name = "log-audit-example"

  variable_map {
    oss_enabled        = true
    actiontrail_enabled = true
    # rds_enabled not set -> RDS activity is not audited
  }
}
```

## Remediated example
```hcl
resource "alicloud_log_audit" "example" {
  display_name = "log-audit-example"

  variable_map {
    oss_enabled         = true
    actiontrail_enabled = true
    rds_enabled         = true  # <-- added: enables RDS activity auditing
  }
}
```

## Remediation steps
1. Locate (or create) the `alicloud_log_audit` resource used for centralized audit logging.
2. Add `rds_enabled = true` inside its `variable_map` block.
3. Verify the RDS instances that should be audited are within the scope/region covered by the log audit configuration.
4. Confirm downstream retention and alerting rules in the Log Service project cover the newly ingested RDS audit logs.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/LogAuditRDSEnabled.py)
