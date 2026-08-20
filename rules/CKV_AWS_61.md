# CKV_AWS_61: Ensure AWS IAM policy does not allow assume role permission across all services
## Severity
**HIGH** (score: 7.5/10)

A trust policy allowing sts:AssumeRole from any AWS service or principal (wildcard) lets essentially any AWS entity assume the role, which is a direct path to full privilege escalation and account compromise.

## Summary
This check flags IAM role trust policies whose `Principal.AWS` value is a raw 12-digit AWS account ID or an `arn:aws:iam::<account-id>:root` ARN, which grants the assume-role permission to the entire target AWS account rather than a specific IAM principal within it.

## Applicability
- **CloudFormation**: `AWS::IAM::Role`, property `Properties/AssumeRolePolicyDocument`.
- **Terraform**: `aws_iam_role` resource, attribute `assume_role_policy`.

## Why it matters
Granting `Principal: { "AWS": "arn:aws:iam::123456789012:root" }` (or the bare account ID) in a trust policy means "any IAM principal in account 123456789012 that has `sts:AssumeRole` permission on their own side can assume this role" — it delegates trust to the entire account rather than a specific, auditable IAM user or role. This is dangerous in cross-account scenarios because it removes the granularity of "which specific team/service/role in the partner account should be trusted," making the effective set of assumers dependent entirely on the other account's internal IAM configuration, which you do not control and cannot audit. If that account is later compromised, or a new IAM user is created there with permissive assume-role rights, they instantly gain access to your role too, without any change on your side. Scoping to a specific IAM role/user ARN in the trusted account, by contrast, means only that named principal can assume the role, giving a clear, minimal, auditable trust boundary.

## How Checkov evaluates this
Both implementations parse `AssumeRolePolicyDocument` into a policy dict (handling `Fn::Sub` in CloudFormation, JSON string parsing in both), then examine `Statement`:
- Skip statements where `Effect == "Deny"`.
- Look at `Principal.AWS`.
- **CloudFormation**: only inspects the **first** statement's `Principal.AWS`, and only if it's a list whose first element is a string; that string is matched against the regex `\d{12}|arn:aws:iam::\d{12}:root`. If it matches → **FAIL**.
- **Terraform**: iterates **all** statements; `Principal.AWS` can be a string or list of strings; each candidate is matched against the same regex `\d{12}|arn:aws:iam::\d{12}:root`. Any match → **FAIL**.
- If parsing fails, CloudFormation returns `UNKNOWN`; Terraform also returns `UNKNOWN`.
- Otherwise → **PASS**.

Note the regex `\d{12}` also matches a bare 12-digit-account-ID-looking substring appearing anywhere in the principal, not just an exact match — be aware of false positives if an ARN happens to embed 12 consecutive digits elsewhere, though in practice `Principal.AWS` values are almost always exactly an account ID or root ARN.

## Non-compliant example
```hcl
resource "aws_iam_role" "partner_access" {
  name = "partner-integration-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::444455556666:root" }  # non-compliant: whole account
        Action    = "sts:AssumeRole"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_role" "partner_access" {
  name = "partner-integration-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::444455556666:role/partner-sync-service"  # fixed: specific role
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = { "sts:ExternalId" = "shared-secret-id" }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Replace the account-root principal with the ARN of the specific IAM role or user in the trusted account that should be allowed to assume this role.
2. Coordinate with the owner of the trusted account to obtain the exact role/user ARN they will use.
3. Add an `sts:ExternalId` condition for third-party/cross-account trust relationships to mitigate the confused-deputy problem.
4. If you genuinely need to trust "any principal in this account" as a deliberate, reviewed design (e.g., a shared services account you also control), document the exception since this pattern is inherently broader than principle-of-least-privilege.
5. This is a metadata-only, non-disruptive change to the role's trust policy.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMRoleAllowAssumeFromAccount.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMRoleAllowAssumeFromAccount.py)
- [AWS: How to use trust policies with IAM roles](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/)
