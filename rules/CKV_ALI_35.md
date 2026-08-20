# CKV_ALI_35: Ensure RDS instance has log_duration enabled
## Severity
**LOW** (score: 2.0/10)

Missing log_duration on RDS reduces query-performance and forensic visibility but is an operational/audit gap rather than a direct exploit path.

## Summary
This check ensures that the Alibaba Cloud RDS (PostgreSQL) database parameter `log_duration` is enabled, so the execution duration of each SQL statement is recorded in the database logs.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `alicloud_db_instance`

## Why it matters
`log_duration` is a PostgreSQL logging parameter that records how long each statement took to execute. Without it, operators lack visibility into query performance regressions and cannot correlate slow or anomalous queries with potential denial-of-service conditions, abusive queries, or exploitation attempts (e.g., SQL injection payloads that run unusually long or unusually short compared to expected patterns). During incident response or forensic investigation, the absence of duration data makes it much harder to reconstruct the timeline and impact of a database-layer attack or to distinguish legitimate load spikes from malicious activity. Many compliance frameworks (e.g., PCI-DSS, SOC 2) require sufficient audit logging of database activity, and query duration is a standard component of that baseline.

## How Checkov evaluates this
This check subclasses the shared `AbsRDSParameter` base check (used by several Alibaba RDS logging checks), configured with `parameter="log_duration"`. It inspects the `alicloud_db_instance` resource's parameter configuration blocks (Alibaba RDS instance parameters are typically set via nested `parameters`/similar blocks mapping parameter name to value) looking for an entry where the parameter name is `log_duration`.
- **FAIL** if the `log_duration` parameter is absent, or is set to a value other than `"on"`/enabled.
- **PASS** if a parameter entry sets `log_duration` to `"on"`.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "PostgreSQL"
  engine_version   = "14.0"
  instance_type    = "rds.pg.s2.large"
  instance_storage = "20"

  # no parameter for log_duration -> logging of statement duration disabled
}
```

## Remediated example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "PostgreSQL"
  engine_version   = "14.0"
  instance_type    = "rds.pg.s2.large"
  instance_storage = "20"

  parameters {
    name  = "log_duration"
    value = "on"  # <-- added: enables logging of statement execution duration
  }
}
```

## Remediation steps
1. Add a `parameters` block to the `alicloud_db_instance` resource with `name = "log_duration"` and `value = "on"`.
2. Confirm the engine is PostgreSQL-family, since `log_duration` is a PostgreSQL-specific parameter (this check targets `alicloud_db_instance`, which also covers MySQL/SQL Server — verify the parameter is applicable to your engine).
3. Apply the change; parameter group updates on Alibaba RDS can require an instance restart depending on the parameter's mutability class — plan for a maintenance window.
4. Pair with `log_connections` (CKV_ALI_37) and `log_disconnections` (CKV_ALI_36) for a more complete audit trail.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSInstanceLogsEnabled.py)
