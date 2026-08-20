# CKV_AWS_172: Ensure QLDB ledger has deletion protection enabled

## Severity
**LOW** (score: 2.0/10)

Missing deletion protection on a QLDB ledger is primarily an availability/data-integrity risk (accidental or malicious deletion of an immutable ledger), not a direct confidentiality or access-control exposure.

## Summary
This check requires that Amazon QLDB ledgers have deletion protection enabled, preventing the ledger (and its immutable transaction history) from being accidentally or maliciously deleted.

## Applicability
- **Terraform**: `aws_qldb_ledger`
- **CloudFormation**: `AWS::QLDB::Ledger`

## Why it matters
QLDB is purpose-built to maintain a complete, immutable, cryptographically verifiable history of every change made to a set of data — commonly used for audit trails, compliance records, financial ledgers, or supply-chain provenance where the guarantee of "this record cannot be altered or destroyed" is the entire point of using the service. If deletion protection is disabled, a single mistaken `terraform destroy`, an errant `DeleteLedger` API call (via compromised credentials, a buggy automation script, or human error), or a malicious insider action can permanently destroy that entire audit history with no recovery path — directly undermining any compliance or non-repudiation guarantee the ledger was meant to provide.

Deletion protection acts as a mandatory manual safeguard: even a principal with `qldb:DeleteLedger` permission cannot delete the ledger until deletion protection is explicitly disabled first, adding a deliberate two-step barrier against both accidental and unauthorized destructive actions.

## How Checkov evaluates this
**Terraform**: the check inspects the `deletion_protection` attribute on `aws_qldb_ledger`. Notably, the check is configured with `missing_block_result=CheckResult.PASSED` — if the attribute is omitted, the check treats it as passing, reflecting that AWS's own default for `deletion_protection` is `true`. If the attribute is explicitly present and set to `false`, the check **FAILS**.

**CloudFormation**: the check inspects `Properties.DeletionProtection`. If the property is absent from the resource entirely, the check explicitly **PASSES** (deletion protection defaults to enabled). If present, it must be `true`, otherwise the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_qldb_ledger" "audit_log" {
  name                = "audit-log"
  permissions_mode    = "STANDARD"
  deletion_protection = false
}
```

## Remediated example
```hcl
resource "aws_qldb_ledger" "audit_log" {
  name                = "audit-log"
  permissions_mode    = "STANDARD"
  deletion_protection = true  # changed from false
}
```

## Remediation steps
1. Set `deletion_protection = true` explicitly (Terraform) or `DeletionProtection: true` (CloudFormation), or simply omit the attribute since it defaults to enabled — the important thing is to never explicitly set it to `false` for production ledgers.
2. If a ledger genuinely needs to be deleted (e.g. decommissioning a test environment), disable deletion protection deliberately as a separate, reviewed change immediately before the deletion, rather than leaving it permanently disabled.
3. This is an in-place, non-disruptive setting change with no downtime.
4. Pair this control with IAM policies that restrict who can call `qldb:UpdateLedger` (to flip deletion protection) and `qldb:DeleteLedger`, so the protection itself cannot be trivially bypassed by any principal with ledger access.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/QLDBLedgerDeletionProtection.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/QLDBLedgerDeletionProtection.py
- AWS docs: https://docs.aws.amazon.com/qldb/latest/developerguide/deletion-protection.html
