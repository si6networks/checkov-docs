# CKV_AWS_15: Ensure IAM password policy requires at least one uppercase letter
## Severity
**LOW** (score: 2.0/10)

Requiring an uppercase character in IAM user passwords is one layer of password complexity that reduces (but does not eliminate) brute-force/guessing risk, making this a meaningful but partial control against account compromise rather than a critical gap on its own.

## Summary
This check verifies that the AWS account's IAM password policy requires passwords to contain at least one uppercase letter.

## Applicability
Terraform only. Applies to the `aws_iam_account_password_policy` resource (a singleton, account-wide setting).

## Why it matters
IAM password policy complexity requirements are a baseline defense against credential-guessing and offline brute-force attacks on any IAM user with console access. Requiring a mix of character classes (uppercase, lowercase, numbers, symbols) increases the effective keyspace an attacker must search, making dictionary and brute-force attacks meaningfully harder, and is a standard control mapped directly to CIS AWS Foundations Benchmark requirements. While MFA is the stronger control, password complexity remains a compensating control for accounts/situations where MFA isn't yet enforced, and auditors (CIS, PCI-DSS, SOC 2) commonly check for it explicitly.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting the `require_uppercase_characters` attribute of `aws_iam_account_password_policy`. Passes when `require_uppercase_characters = true`; fails when it is `false` or left unset (AWS defaults this to `false` if omitted).

## Non-compliant example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  # require_uppercase_characters not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  require_uppercase_characters   = true # <-- added
}
```

## Remediation steps
1. Add (or set to `true`) `require_uppercase_characters` on the `aws_iam_account_password_policy` resource.
2. Since this resource is a singleton per account, ensure only one `aws_iam_account_password_policy` resource is defined across your Terraform state to avoid conflicting applies.
3. Pair this with the other complexity flags (`require_lowercase_characters`, `require_numbers`, `require_symbols`) and a reasonable `minimum_password_length` (14+ recommended) and `max_password_age`/`password_reuse_prevention`.
4. Existing IAM users are not forced to change their password immediately unless you also set `hard_expiry` or otherwise force a rotation — the new policy only applies going forward / at next required rotation.
5. Longer term, prefer enforcing MFA and moving users to federated/SSO access rather than relying solely on password policy.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/PasswordPolicyUppercaseLetter.py
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
