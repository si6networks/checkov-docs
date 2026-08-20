# CKV_AWS_170: Ensure QLDB ledger permissions mode is set to STANDARD

## Severity
**MEDIUM** (score: 5.0/10)

Setting QLDB permissions mode to ALLOW_ALL (instead of STANDARD) grants all authenticated principals full read/write/admin access to the ledger regardless of their IAM policy, functioning like an implicit wildcard permission on a data-integrity-critical resource.

## Summary
This check requires that Amazon QLDB (Quantum Ledger Database) ledgers use the `STANDARD` permissions mode, which enforces fine-grained IAM authorization on every ledger operation, rather than the legacy `ALLOW_ALL` mode.

## Applicability
- **Terraform**: `aws_qldb_ledger`
- **CloudFormation**: `AWS::QLDB::Ledger`

## Why it matters
QLDB's `ALLOW_ALL` permissions mode is a legacy compatibility mode that grants any IAM principal with basic QLDB API access broad, unrestricted permissions to read and write ledger data and documents — it largely bypasses fine-grained IAM policy enforcement at the document/table level. Because QLDB is specifically designed to provide an immutable, cryptographically verifiable transaction log (used for audit trails, financial records, supply-chain provenance, etc.), a permissions model that doesn't enforce granular access control undermines the core value proposition: if any principal with API access can read or write broadly, sensitive ledger data can be exposed or, more critically, the assumption that only authorized parties can append/query specific data is broken.

`STANDARD` mode enforces IAM policies scoped to specific QLDB actions and resources (including PartiQL statement-level permissions), aligning ledger access control with the principle of least privilege and making it possible to restrict which principals can query or mutate specific tables within the ledger.

## How Checkov evaluates this
The check inspects the `permissions_mode` attribute (Terraform) / `Properties.PermissionsMode` (CloudFormation) on the QLDB ledger resource. It **PASSES** only if the value is exactly `"STANDARD"`; any other value (notably the legacy `"ALLOW_ALL"`), or omitting the attribute, causes the check to **FAIL**.

## Non-compliant example
```hcl
resource "aws_qldb_ledger" "audit_log" {
  name                = "audit-log"
  permissions_mode    = "ALLOW_ALL"
  deletion_protection = true
}
```

## Remediated example
```hcl
resource "aws_qldb_ledger" "audit_log" {
  name                = "audit-log"
  permissions_mode    = "STANDARD"  # changed from ALLOW_ALL
  deletion_protection = true
}
```

## Remediation steps
1. Set `permissions_mode = "STANDARD"` (Terraform) or `PermissionsMode: STANDARD` (CloudFormation) on the QLDB ledger resource.
2. Note: `permissions_mode` typically cannot be changed on an existing ledger in-place via a simple update in all provider versions — verify against current AWS/Terraform provider behavior, as switching from `ALLOW_ALL` may require recreating the ledger or a supported in-place transition depending on API/provider support at the time of change; test in a non-production environment first.
3. Before switching to `STANDARD`, audit and define IAM policies granting the specific QLDB actions (e.g. `qldb:SendCommand`, PartiQL statement permissions) each principal/application needs — under `STANDARD` mode, access not explicitly granted will be denied, which can break existing integrations that relied on `ALLOW_ALL`'s implicit broad access.
4. Test all applications and pipelines that read/write the ledger against the new permissions mode in a staging environment before rolling out to production.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/QLDBLedgerPermissionsMode.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/QLDBLedgerPermissionsMode.py
- AWS docs: https://docs.aws.amazon.com/qldb/latest/developerguide/security_iam_id-based-policy-examples.html
