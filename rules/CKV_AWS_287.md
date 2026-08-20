# CKV_AWS_287: Ensure IAM policies does not allow credentials exposure
## Severity
**HIGH** (score: 7.5/10)

IAM policies that allow retrieval or exposure of credentials (e.g. access keys, passwords, login profiles) enable an attacker with those permissions to obtain long-lived secrets and pivot to further compromise.

## Summary
This check fails when an IAM policy document grants actions that can expose or read other principals' credential material (e.g., IAM access keys, login profiles, service-specific credentials), a known category of IAM risk flagged by the cloudsplaining engine.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resources:** `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`

## Why it matters
"Credentials exposure" actions are IAM permissions that let a principal retrieve, create, or update login/access-key material belonging to another IAM identity — for example, `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, or `iam:GetAccessKeyLastUsed` used in combination with other actions. If a compromised or malicious principal holds such permissions unconditionally, they can mint new long-lived access keys for a more-privileged user, reset another user's console password, or otherwise obtain durable credentials that persist even after the original access is revoked — a classic technique for establishing backdoor persistence in an AWS account. Because these actions target *other* IAM identities rather than the caller's own account, they are especially dangerous when granted broadly (`Resource: "*"`), since they enable lateral movement and privilege consolidation.

## How Checkov evaluates this
The check is implemented via `BaseTerraformCloudsplainingResourceIAMCheck`, delegating to cloudsplaining's `PolicyDocument.credentials_exposure` property, which matches the policy's actions against its curated list of credential-exposure actions. The check explicitly excludes `ecr:GetAuthorizationToken` from consideration (`excluded_actions = {"ecr:GetAuthorizationToken"}`) since it is a routine, low-risk action needed for standard ECR docker-login workflows and is not a meaningful escalation vector on its own. Any other matched actions after that exclusion cause a **FAIL**; an empty result **passes**.

## Non-compliant example
```hcl
resource "aws_iam_policy" "bad" {
  name = "credentials-exposure-risk"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreateAccessKey", "iam:CreateLoginProfile"]
        Resource = "*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "good" {
  name = "scoped-credential-management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreateAccessKey"]
        Resource = "arn:aws:iam::123456789012:user/${aws:username}"
      }
    ]
  })
}
```

## Remediation steps
1. Identify which credential-management actions (`iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:UpdateAccessKey`, etc.) are present via the Checkov/cloudsplaining finding output.
2. Restrict `Resource` to the caller's own IAM identity (e.g., using the `${aws:username}` policy variable) rather than `"*"`, so principals can only manage their own credentials, not others'.
3. Remove any credential-management actions not strictly required by the principal's role — most application/service roles never need them at all.
4. If a dedicated "IAM admin" role legitimately needs these permissions organization-wide, isolate them into a break-glass role with MFA enforcement and strong monitoring/alerting on use, rather than embedding them in general-purpose policies.
5. Re-scan with Checkov after tightening the `Resource` scope or removing actions to confirm the finding clears.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMCredentialsExposure.py
- cloudsplaining docs: https://cloudsplaining.readthedocs.io/en/latest/glossary/credentials-exposure.html
