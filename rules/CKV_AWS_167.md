# CKV_AWS_167: Ensure Glacier Vault access policy is not public by only allowing specific services or principals to access it

## Severity
**MEDIUM** (score: 5.0/10)

A Glacier Vault access policy that permits any principal grants effectively public access to archived data, analogous to a public S3 bucket policy, and can allow unauthorized read/write of long-term stored (often sensitive/compliance) data.

## Summary
This check requires that an S3 Glacier Vault's access policy does not grant broad, effectively-public access (e.g. `Principal: "*"` without adequate restriction), by analyzing the policy for internet-accessible actions.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_glacier_vault` (`access_policy` attribute)

## Why it matters
Glacier vaults are commonly used for long-term archival of backups, compliance records, and other cold-storage data — often the last line of defense if primary data stores are compromised or deleted. A vault access policy that allows a wildcard principal (`"*"`) or otherwise fails to restrict which AWS accounts/services/roles can call vault operations effectively makes archived data (or the ability to delete/modify it) accessible to anyone, including unauthenticated or unintended external parties, depending on other conditions in the policy.

Because Glacier is typically used for infrequently-accessed archival data, misconfigurations here can go unnoticed for a long time (unlike an S3 bucket serving live traffic where public access might be noticed quickly), making it an attractive target for data exfiltration or destructive access that undermines the vault's purpose as a recovery/compliance safety net.

## How Checkov evaluates this
The check reads the `access_policy` attribute of `aws_glacier_vault`. If the attribute is absent, the check **PASSES** (no explicit policy means Glacier's default deny-all behavior applies). If `access_policy` references a `.json`-templated string that looks like a `templatefile()`/interpolation pattern the check cannot statically resolve, it returns `UNKNOWN`. Otherwise, it parses the policy JSON and uses the `cloudsplaining` library's `ResourcePolicyDocument` to detect `internet_accessible_actions` — actions any principal (unrestricted by conditions) could invoke. If any such actions are found, the check **FAILS**; if the policy can't be parsed as valid policy JSON, it returns `UNKNOWN`.

## Non-compliant example
```hcl
resource "aws_glacier_vault" "compliance_archive" {
  name = "compliance-archive"

  access_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAll"
        Effect    = "Allow"
        Principal = "*"
        Action    = "glacier:*"
        Resource  = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_glacier_vault" "compliance_archive" {
  name = "compliance-archive"

  access_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowBackupRoleOnly"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/backup-service-role"  # scoped principal, not "*"
        }
        Action   = ["glacier:UploadArchive", "glacier:InitiateJob", "glacier:GetJobOutput"]
        Resource = "arn:aws:glacier:us-east-1:123456789012:vaults/compliance-archive"
      }
    ]
  })
}
```

## Remediation steps
1. Remove wildcard (`"*"`) principals from the vault's `access_policy`; scope the `Principal` element to specific AWS account ARNs, IAM role ARNs, or AWS service principals that legitimately need access.
2. If cross-account access is required, use a specific account ID/role ARN plus an `aws:SourceAccount`/`aws:SourceArn` condition rather than a bare wildcard.
3. Scope `Action` to only the operations needed (e.g. `glacier:UploadArchive`, `glacier:InitiateJob`) rather than `glacier:*`.
4. If you don't need a custom policy at all, simply omit `access_policy` — Glacier vaults default to private, account-owner-only access.
5. If your policy is built via `templatefile()` or another dynamic construct Checkov cannot statically evaluate, consider adding a suppression comment with justification after manual review, since the check will report `UNKNOWN` rather than a definitive pass.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/GlacierVaultAnyPrincipal.py
- AWS docs: https://docs.aws.amazon.com/amazonglacier/latest/dev/vault-access-policy.html
