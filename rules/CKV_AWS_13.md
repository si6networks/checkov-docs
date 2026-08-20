# CKV_AWS_13: Ensure IAM password policy prevents password reuse

## Severity
**HIGH** (score: 7.5/10)

Allowing password reuse weakens the account password policy and makes credential-stuffing/reuse-based compromise somewhat more likely, but it is only one layer in a defense-in-depth authentication posture.

## Summary
This check requires the account-wide IAM password policy to set `password_reuse_prevention` to at least 24, so users cannot recycle recently-used passwords.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_iam_account_password_policy`

## Why it matters
Without reuse prevention, a user can simply toggle between two or three passwords whenever a password rotation policy forces a change (e.g., alternate "Password1!" and "Password2!"). This defeats the security purpose of password expiration: any password that leaks (via phishing, credential-stuffing lists, or a breached third-party service where the same password was reused) remains valid indefinitely because the user can rotate back to it after a forced change instead of choosing a genuinely new secret. Preventing reuse of the last 24 passwords forces meaningful password rotation and reduces the window in which a previously compromised credential can be reused to gain IAM console or CLI access.

## How Checkov evaluates this
The check inspects the `password_reuse_prevention` attribute on `aws_iam_account_password_policy`:
- If the key is present, Checkov reads its value; if it's a Terraform variable reference it cannot resolve, the result is **UNKNOWN**.
- Otherwise it coerces the value to an integer and evaluates: **PASS** if the value is truthy AND **not** less than 24 (i.e., `reuse_prevention >= 24`); otherwise it falls through to **FAIL**.
- If the key is absent entirely, the check **FAILS** (no default reuse prevention is assumed).

In short: to pass, `password_reuse_prevention` must be set explicitly to `24` or higher.

## Non-compliant example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  max_password_age               = 90
  # password_reuse_prevention not set, or set below 24 -> FAIL
}
```

## Remediated example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  max_password_age               = 90
  password_reuse_prevention      = 24   # added, prevents reuse of last 24 passwords
}
```

## Remediation steps
1. Add `password_reuse_prevention = 24` (AWS's maximum allowed value) to the `aws_iam_account_password_policy` resource.
2. Remember this resource is a singleton per AWS account — there can be only one `aws_iam_account_password_policy`; ensure you aren't managing conflicting policies in multiple Terraform states.
3. Pair this with `max_password_age` (forced rotation) so the reuse-prevention control has a rotation trigger to act against.
4. This is a non-disruptive, account-level setting change with no resource replacement or downtime.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/PasswordPolicyReuse.py)
- [AWS: Setting an account password policy for IAM users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html)
