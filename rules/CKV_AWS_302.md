# CKV_AWS_302: Ensure DB Snapshots are not Public
## Severity
**CRITICAL** (score: 9.0/10)

This check verifies RDS DB snapshots are not shared with all AWS accounts, and a public snapshot exposes a full copy of the database's data (including any secrets or PII it contains) to anyone.

## Summary
This check ensures an `aws_db_snapshot` resource's `shared_accounts` list does not contain the value `"all"`, which would make the RDS database snapshot publicly restorable by any AWS account.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_db_snapshot`

## Why it matters
An RDS database snapshot is a full point-in-time copy of a database's data, including all tables, rows, and typically embedded credentials, PII, and other sensitive business data. Sharing a snapshot with `"all"` makes it restorable by literally any AWS account in the world — this is one of the most common and severe real-world cloud data breach patterns (numerous public breaches have resulted from accidentally public RDS/EBS snapshots). Once shared publicly, an attacker can simply restore the snapshot into their own account and browse the full database contents at their leisure, entirely outside your monitoring, logging, or access control — you would have no visibility into who accessed the data or when.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` (Python check) with `"all"` as the forbidden value. It inspects the `shared_accounts` attribute:
- **FAIL** if `shared_accounts` includes `"all"`.
- **PASS** if `shared_accounts` is absent, empty, or contains only specific AWS account IDs (not the `"all"` wildcard).

## Non-compliant example
```hcl
resource "aws_db_snapshot" "example" {
  db_instance_identifier = aws_db_instance.example.id
  db_snapshot_identifier = "example-snapshot"
}

resource "aws_db_snapshot_share" "example" {
  # illustrative: sharing configured via shared_accounts
}

resource "aws_db_snapshot" "shared" {
  db_instance_identifier = aws_db_instance.example.id
  db_snapshot_identifier = "shared-snapshot"
  shared_accounts         = ["all"]   # public snapshot -> check FAILS
}
```

## Remediated example
```hcl
resource "aws_db_snapshot" "shared" {
  db_instance_identifier = aws_db_instance.example.id
  db_snapshot_identifier = "shared-snapshot"
  shared_accounts         = ["123456789012"]   # scoped to specific, known AWS account(s)
}
```

## Remediation steps
1. Remove `"all"` from the `shared_accounts` list on every `aws_db_snapshot` resource.
2. If cross-account sharing is genuinely required, list only the specific AWS account ID(s) that need access.
3. Audit existing snapshots in the AWS console/CLI (`aws rds describe-db-snapshot-attributes`) for any that are already public and revoke that sharing immediately (`aws rds modify-db-snapshot-attribute --values-to-remove all`).
4. Consider enabling AWS Config rule `rds-snapshots-public-prohibited` or an SCP that blocks public snapshot sharing account-wide as a defense-in-depth backstop against future misconfiguration.
5. If snapshots must be shared broadly for legitimate purposes (e.g., a public dataset), ensure the data has been scrubbed of all sensitive/regulated content first and treat this as a deliberate, reviewed exception.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DBSnapshotsArePrivate.py)
