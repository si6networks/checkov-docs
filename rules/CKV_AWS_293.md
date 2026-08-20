# CKV_AWS_293: Ensure that AWS database instances have deletion protection enabled
## Severity
**MEDIUM** (score: 5.0/10)

This check verifies RDS instance deletion protection is enabled; its absence is an availability/operational-safety gap (accidental or malicious deletion) rather than a direct confidentiality or access-control weakness.

## Summary
This check ensures every `aws_db_instance` (RDS instance) has `deletion_protection` set to `true` so it cannot be accidentally or maliciously deleted.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_db_instance`

## Why it matters
Without deletion protection, an RDS instance can be destroyed by a single API call, console click, or an erroneous `terraform destroy` / `terraform apply` that replaces the resource — with no confirmation step from AWS itself. For production databases this is a severe operational risk: loss of the instance means loss of all data not captured in the most recent backup/snapshot, potential extended outages while restoring, and in the worst case irrecoverable data loss if backups are also misconfigured or expired. This is a reliability/availability control as much as a security one — it guards against destructive human error, compromised credentials being used to sabotage infrastructure, and automation bugs that could inadvertently target and drop a live database resource.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check). It inspects the `deletion_protection` attribute on `aws_db_instance`:
- **PASS** if `deletion_protection = true`.
- **FAIL** if the attribute is missing (AWS default is `false`) or explicitly set to `false`.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier        = "app-prod-db"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.r6g.large"
  allocated_storage = 100
  username          = "dbadmin"
  password          = var.db_password
  # deletion_protection not set -> defaults to false, check FAILS
}
```

## Remediated example
```hcl
resource "aws_db_instance" "app_db" {
  identifier          = "app-prod-db"
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.r6g.large"
  allocated_storage   = 100
  username            = "dbadmin"
  password            = var.db_password
  deletion_protection = true   # prevents accidental/malicious deletion
}
```

## Remediation steps
1. Add `deletion_protection = true` to every production (and ideally non-production) `aws_db_instance` resource.
2. If you ever need to actually delete a protected instance intentionally, first set `deletion_protection = false`, apply, then delete — this is a deliberate two-step safeguard, not a bug.
3. Combine with `skip_final_snapshot = false` (or a `final_snapshot_identifier`) so that even an intentional deletion produces a recoverable final snapshot.
4. For environments managed via Terraform where the resource might be replaced (e.g., due to `engine_version` forcing replacement), verify that deletion protection doesn't block a legitimate `terraform apply` — you may need to temporarily disable it for planned replacements.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSInstanceDeletionProtection.py)
