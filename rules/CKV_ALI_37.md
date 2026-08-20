# CKV_ALI_37: Ensure RDS instance has log_connections enabled
## Severity
**LOW** (score: 2.0/10)

Missing log_connections removes visibility into who is connecting to the database, hampering detection of unauthorized access attempts.

## Summary
This check ensures that the Alibaba Cloud RDS (PostgreSQL) database parameter `log_connections` is enabled, so every new session connection to the database is recorded in the database logs.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `alicloud_db_instance`

## Why it matters
`log_connections` records who connected to the database, from where, and when. Without this, there is no audit record of connection attempts, making it impossible to detect brute-force login attempts, unauthorized access from unexpected source addresses, or credential-stuffing activity targeting the database directly. Connection logging is one of the most fundamental audit controls for a database — it is the equivalent of an authentication log for the data tier — and its absence significantly weakens an organization's ability to detect and investigate unauthorized data access, which is frequently mandated by compliance frameworks such as PCI-DSS and HIPAA for systems handling regulated data.

## How Checkov evaluates this
This check subclasses the shared `AbsRDSParameter` base check, configured with `parameter="log_connections"`. It inspects the `alicloud_db_instance` resource's parameter configuration for an entry named `log_connections`.
- **FAIL** if the `log_connections` parameter is absent or not set to `"on"`.
- **PASS** if a parameter entry sets `log_connections` to `"on"`.

## Non-compliant example
```hcl
resource "alicloud_db_instance" "example" {
  engine           = "PostgreSQL"
  engine_version   = "14.0"
  instance_type    = "rds.pg.s2.large"
  instance_storage = "20"

  # no parameter for log_connections -> new connections are not logged
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
    name  = "log_connections"
    value = "on"  # <-- added: enables logging of new session connections
  }
}
```

## Remediation steps
1. Add a `parameters` block to the `alicloud_db_instance` resource with `name = "log_connections"` and `value = "on"`.
2. Confirm the parameter applies to the RDS engine/version deployed (PostgreSQL-family).
3. Apply the change and check whether it requires an instance restart per the Alibaba Cloud RDS parameter documentation.
4. Route the resulting logs to a centralized SIEM/log-analysis pipeline so connection anomalies can be alerted on, not just recorded.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RDSInstanceLogConnections.py)
