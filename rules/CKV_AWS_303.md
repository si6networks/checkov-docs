# CKV_AWS_303: Ensure SSM documents are not Public
## Severity
**HIGH** (score: 7.5/10)

This check verifies SSM documents are not shared publicly with all AWS accounts; a public automation/command document can leak operational logic, embedded parameters, or internal infrastructure details and can potentially be a vector for command execution guidance abuse.

## Summary
This check ensures that an `aws_ssm_document` resource's first permissions block does not grant access to `account_ids = ["All"]`, which would make the SSM document publicly shared with every AWS account.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_ssm_document`

## Why it matters
AWS Systems Manager (SSM) documents define automation runbooks, command documents, and configuration scripts that can execute arbitrary commands on managed EC2 instances or perform automation actions across your AWS environment. A publicly shared SSM document (`account_ids = "All"`) is visible and usable by any AWS account, which can leak sensitive operational details: internal hostnames, IP ranges, deployment procedures, embedded configuration values, or even credentials/tokens that were carelessly included in a script parameter or command body. Beyond information disclosure, if the document also references or is intended to be run against your resources by other automation, exposing its content publicly reveals your operational security posture and internal architecture to potential attackers performing reconnaissance, and could be copied/misused to attack similarly-configured environments elsewhere. This maps to NIST 800-53 access control requirements (AC-3, AC-4, AC-6, SC-7) for restricting access to systems automation.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` (Python check) with `"All"` as the forbidden value. It inspects the nested attribute path `permissions[0].account_ids`:
- **FAIL** if the first `permissions` block's `account_ids` is set to `"All"`.
- **PASS** if `permissions` is absent, or `account_ids` lists only specific AWS account IDs (not the `"All"` wildcard).

## Non-compliant example
```hcl
resource "aws_ssm_document" "example" {
  name          = "example-runbook"
  document_type = "Command"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Example command document"
    mainSteps     = []
  })

  permissions = {
    type        = "Share"
    account_ids = "All"   # publicly shared -> check FAILS
  }
}
```

## Remediated example
```hcl
resource "aws_ssm_document" "example" {
  name          = "example-runbook"
  document_type = "Command"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Example command document"
    mainSteps     = []
  })

  permissions = {
    type        = "Share"
    account_ids = "123456789012,234567890123"   # scoped to specific known accounts
  }
}
```

## Remediation steps
1. Change `account_ids` in the `permissions` block from `"All"` to a comma-separated list (per the AWS provider's expected format) of specific AWS account IDs that legitimately need access.
2. If the document does not need to be shared cross-account at all, remove the `permissions` block entirely so it defaults to private (only accessible within the owning account).
3. Audit existing SSM documents for public sharing via `aws ssm describe-document-permission --name <doc> --permission-type Share` and revoke any unintended public grants.
4. Review document content for embedded secrets or sensitive internal details before any legitimate cross-account or public sharing, since sharing controls access but doesn't retroactively redact content already viewed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SSMDocumentsArePrivate.py)
