# CKV_AWS_11: Ensure IAM password policy requires at least one lowercase letter

## Severity
**LOW** (score: 2.0/10)

Omitting the lowercase-character requirement weakens password complexity and brute-force resistance, but the account password policy is not fully disabled and other controls (length, MFA) may still apply.

## Summary
Fails when the AWS account's IAM password policy does not require at least one lowercase character in user passwords.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_iam_account_password_policy` resource.

## Why it matters
The IAM account password policy is the account-wide baseline that governs how console users must construct their passwords. Weak composition rules (no requirement for mixed case, numbers, or symbols) shrink the effective keyspace of passwords, making them meaningfully easier to guess or crack via offline brute-force/dictionary attacks if credentials or hashes are ever leaked, and easier to guess in online credential-stuffing/spraying attempts. Requiring a lowercase character is one of several composition requirements (uppercase, numbers, symbols, minimum length) that collectively raise the cost of password guessing attacks and are commonly mandated by compliance frameworks (CIS AWS Foundations, PCI-DSS, NIST 800-63).

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `require_lowercase_characters` attribute of the `aws_iam_account_password_policy` resource:
- **PASS**: `require_lowercase_characters = true`
- **FAIL**: `require_lowercase_characters = false`, or the attribute is absent (default value check treats a missing/false attribute as failing since AWS's own default for this setting is `false`).

## Non-compliant example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = false
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
}
```

## Remediated example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
}
```

## Remediation steps
1. Locate (or create) the single `aws_iam_account_password_policy` resource for the account — there can only be one per account, so check for duplicates/conflicts across modules.
2. Set `require_lowercase_characters = true`.
3. While editing, also confirm `require_uppercase_characters`, `require_numbers`, `require_symbols`, and a sufficient `minimum_password_length` (14+ recommended) are set, since these are covered by sibling Checkov rules (CKV_AWS_13, CKV_AWS_12, CKV_AWS_10, CKV_AWS_9/38).
4. Apply the change — this is an account-level setting with no downtime impact, but existing users' passwords are not automatically invalidated; the new rule only applies at next password change/rotation unless combined with `max_password_age`.
5. If your organization uses IAM Identity Center / SSO exclusively and IAM users are disallowed, this resource may be moot — but sync policy still needs to exist to satisfy CIS-based scanners in many orgs.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/PasswordPolicyLowercaseLetter.py
- AWS documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
