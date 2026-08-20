# CKV_AWS_33: Ensure KMS key policy does not contain wildcard (*) principal
## Severity
**MEDIUM** (score: 5.0/10)

A KMS key policy containing a wildcard ('*') principal can allow any AWS principal (or, if combined with a compromised/anonymous caller, unintended external parties) to use or manage the key, effectively granting uncontrolled access to encrypt/decrypt all data protected by it.

## Summary
This check requires that a KMS key's resource policy does not grant an `Allow` statement to a wildcard (`*`) principal, which would let any AWS identity (in any account, anywhere) use or manage the key.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::KMS::Key` (CloudFormation), `aws_kms_key` (Terraform)

## Why it matters
A KMS key policy is the primary (and for KMS, mandatory) access-control mechanism for the key — IAM policies alone are insufficient without a compatible key policy. If a key policy's `Allow` statement specifies `"Principal": "*"` (or `{"AWS": "*"}`) without a restrictive `Condition`, any AWS principal that can also reach the key through some IAM policy — or in the worst case, literally any AWS account — can perform the actions in that statement (e.g., `kms:Decrypt`, `kms:GenerateDataKey`, or worse, `kms:*`). Because KMS keys often protect the encryption of sensitive data (RDS databases, S3 buckets, Secrets Manager secrets, EBS volumes), a wildcard principal on a permissive key policy can turn into cross-account data exposure or key-deletion/DoS by any external actor who obtains any IAM credentials that reference the key, effectively undermining every other control that assumes the encrypted data is protected.

## How Checkov evaluates this
Two implementations, one per IaC framework, share the same logic:

**Terraform (`KMSKeyWildcardPrincipal.py`):**
- Parses the `policy` attribute (a JSON string) looking for `Statement` entries.
- For each statement: skips it if `Effect == "Deny"` (a Deny doesn't grant access) or if it has a `Condition` block (conditions can legitimately scope down an apparent wildcard, e.g. restricting to `aws:PrincipalOrgID`).
- If `Principal.AWS` or `Principal` itself is the literal string `"*"`, or a list containing `"*"`, the check **FAILS**.
- If the `policy` attribute isn't set at all, or parsing fails, the check **PASSES** (fails open when it can't parse the policy).

**CloudFormation (`KMSKeyWildCardPrincipal.py`):**
- Reads `Properties.KeyPolicy.Statement`.
- Same logic: skips `Deny` statements, checks whether `Principal` (or `Principal.AWS`) equals or contains `"*"` → **FAILS** if so. Note the CloudFormation version does not have the same `Condition`-skip exception the Terraform version has.
- Otherwise **PASSES**.

## Non-compliant example
```hcl
resource "aws_kms_key" "bad_example" {
  description = "Example key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAnyPrincipal"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_kms_key" "good_example" {
  description = "Example key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowRootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowSpecificRoleUse"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:role/app-role" }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}
```

## Remediation steps
1. Replace `"Principal": "*"` (or `{"AWS": "*"}`) with explicit account/role/user ARNs that actually need access to the key.
2. If cross-account or service-wide access is genuinely required (e.g., an AWS service principal like `logs.amazonaws.com`), scope it with a `Condition` block (e.g., `aws:SourceArn`, `aws:SourceAccount`, or `aws:PrincipalOrgID`) rather than leaving it unconditionally open — note the Terraform check will pass a wildcard principal if a `Condition` is present, but review the condition's actual restrictiveness manually since Checkov doesn't validate its content.
3. Never combine a wildcard principal with a broad action like `kms:*` — even a conditioned wildcard should be paired with the minimum necessary actions.
4. Audit existing keys for legacy wildcard statements added for convenience during initial setup; these are common in copy-pasted "default" key policies.
5. Key policy changes take effect immediately and do not require key replacement — but validate you don't lock yourself out (always retain a statement granting the account root user `kms:*`, per AWS recommendation, to avoid an unmanageable key).

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KMSKeyWildcardPrincipal.py)
- [Checkov CloudFormation check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/KMSKeyWildCardPrincipal.py)
- [AWS: Key policies in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html)
