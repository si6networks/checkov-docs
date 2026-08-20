# CKV_ALI_36: Ensure RDS instance has log_disconnections enabled
## Severity
**LOW** (score: 2.0/10)

Without log_disconnections, security teams lose an audit trail of session endings on the database, weakening incident investigation but not itself an active vulnerability.

## Summary
This check ensures that the Alibaba Cloud RDS (PostgreSQL) database parameter `log_disconnections` is enabled, so every session disconnection is recorded in the database logs.

## Applicability
- **Framework:** Terraform
- **Resource type:** `alicloud_db_instance`

## Why it matters
`log_disconnections` records the end of each database session, including its duration. Without this logging, incident responders cannot reliably determine when an attacker's session ended, how long unauthorized access persisted, or whether a session was terminated abnormally (which can itself be a signal of an aborted attack or a crash exploited during exfiltration). Session lifecycle logging (connect + disconnect) is a baseline expectation for database audit trails under most compliance regimes, and asymmetric logging (e.g., logging connections without disconnections) leaves gaps that make timeline reconstruction unreliable during forensic analysis.

## How Checkov evaluates this
This check subclasses the shared `AbsRDSParameter` base check, configured with `parameter="log_disconnections"`. It inspects the `alicloud_db_instance` resource's parameter configuration for an entry named `log_disconnections`.
- **FAIL** if the `log_disconnections` parameter is absent or not set to `"on"`.
- **PASS** if a parameter entry sets `log_disconnections` to `"on"`.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "PostgreSQL"
  engine_version   = "14.0"
  instance_type    = "rds.pg.s2.large"
  instance_storage = "20"

  # no parameter for log_disconnections -> session end events are not logged
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
    name  = "log_disconnections"
    value = "on"  # <-- added: enables logging of session disconnections
  }
}
```

## Remediation steps
1. Add a `parameters` block to the `alicloud_db_instance` resource with `name = "log_disconnections"` and `value = "on"`.
2. Verify this parameter is supported for the specific RDS engine/version in use (PostgreSQL-family).
3. Apply the change; check whether this parameter requires an instance restart in the Alibaba Cloud RDS parameter reference before rolling out to production.
4. Enable `log_connections` (CKV_ALI_37) alongside this to get symmetric session start/end audit records.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSInstanceLogDisconnections.py)
