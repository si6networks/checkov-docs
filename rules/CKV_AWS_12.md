# CKV_AWS_12: Ensure IAM password policy requires at least one number

## Severity
**LOW** (score: 2.0/10)

Omitting the numeric-character requirement weakens password complexity and brute-force resistance without disabling the account password policy outright.

## Summary
Fails when the AWS account's IAM password policy does not require at least one numeric character in user passwords.

## Applicability
- **Terraform**: `aws_iam_account_password_policy` resource.

## Why it matters
As with the lowercase-letter requirement (CKV_AWS_11), requiring numeric characters is a password-composition control that increases the effective keyspace and unpredictability of user passwords. Skipping this requirement makes passwords more susceptible to dictionary attacks and pattern-based guessing (e.g. purely alphabetic passwords are far more likely to be common words or names). This control is part of the standard password-complexity baseline required by frameworks such as CIS AWS Foundations Benchmark, PCI-DSS, and NIST 800-63B-influenced internal policies, and is commonly checked alongside the sibling rules for uppercase, lowercase, symbols, and minimum length.

## How Checkov evaluates this
A `BaseResourceValueCheck` inspecting the `require_numbers` attribute of the `aws_iam_account_password_policy` resource:
- **PASS**: `require_numbers = true`
- **FAIL**: `require_numbers = false` or the attribute is not set (AWS's own default for this setting is `false`).

## Non-compliant example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = false
  require_symbols               = true
}
```

## Remediated example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols               = true
}
```

## Remediation steps
1. Locate the account's single `aws_iam_account_password_policy` resource.
2. Set `require_numbers = true`.
3. While updating, verify the other composition requirements (uppercase, lowercase, symbols) and `minimum_password_length` are also configured per your compliance baseline — these are covered by companion Checkov rules (CKV_AWS_11, CKV_AWS_13, CKV_AWS_9/38).
4. Apply — this is a low-risk, account-wide setting change with no resource downtime; it takes effect for future password changes/creations, not retroactively for existing passwords unless combined with `max_password_age` to force rotation.
5. If your organization has moved entirely to IAM Identity Center/SSO federated access with no native IAM users, confirm whether this resource is still required by your compliance scanning tooling even if no IAM users exist.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/PasswordPolicyNumber.py
- AWS documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
