# CKV_AWS_14: Ensure IAM password policy requires at least one symbol

## Severity
**LOW** (score: 2.0/10)

Not requiring a symbol in account passwords marginally weakens password strength against offline brute-force/guessing, but is a minor factor compared to length, MFA, or lockout controls.

## Summary
This check requires the account-wide IAM password policy to set `require_symbols = true`, so IAM user passwords must contain at least one non-alphanumeric symbol.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_iam_account_password_policy`

## Why it matters
Password complexity requirements (length, character-class diversity) exist to increase the search space an attacker must brute-force or dictionary-attack against. Without a symbol requirement, users are more likely to choose passwords drawn from common word lists or predictable patterns (dictionary words, names, simple number substitutions), which are significantly more susceptible to offline cracking if password hashes are ever exposed, and to online credential-stuffing/guessing attacks. While complexity alone is not a substitute for MFA, it remains a defense-in-depth control mandated by many compliance frameworks (PCI-DSS, CIS AWS Foundations Benchmark) for account password policies, and reduces the effectiveness of automated password-guessing against IAM console logins that don't have MFA enforced yet.

## How Checkov evaluates this
This is a plain attribute-value check (`BaseResourceValueCheck`, default expected value `True`):
- Inspects the `require_symbols` attribute on `aws_iam_account_password_policy`.
- **PASS** if `require_symbols = true`.
- **FAIL** if `false` or unset (AWS's default is `false`).

## Non-compliant example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_numbers               = true
  require_uppercase_characters  = true
  require_lowercase_characters  = true
  # require_symbols not set -> defaults to false -> FAIL
}
```

## Remediated example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_numbers               = true
  require_uppercase_characters  = true
  require_lowercase_characters  = true
  require_symbols               = true   # added
}
```

## Remediation steps
1. Add `require_symbols = true` to the `aws_iam_account_password_policy` resource.
2. Combine with the other password-strength attributes — `require_numbers`, `require_uppercase_characters`, `require_lowercase_characters`, `minimum_password_length` (14+ recommended), and `password_reuse_prevention` (see CKV_AWS_13) — for a complete policy.
3. Enforce MFA for IAM users as a stronger, complementary control; password complexity alone does not prevent credential-stuffing against reused passwords.
4. This is an account-level setting with no resource replacement; existing users are not forced to change their current password immediately, only on their next required rotation, unless `hard_expiry`/rotation settings force it sooner.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/PasswordPolicySymbol.py)
- [AWS: Setting an account password policy for IAM users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html)
