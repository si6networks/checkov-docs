# CKV_AWS_10: Ensure IAM password policy requires minimum length of 14 or greater
## Severity
**LOW** (score: 2.0/10)

Allowing a minimum IAM password length below 14 characters weakens resistance to offline/brute-force password guessing but does not by itself disable authentication or expose a direct attack path.

## Summary
This check ensures the AWS account's IAM password policy enforces a minimum password length of at least 14 characters for IAM users.

## Applicability
**Checkov framework(s):** `terraform`

Terraform resource `aws_iam_account_password_policy` — an account-level, singleton resource that configures the password policy applied to all IAM users in the AWS account.

## Why it matters
IAM user passwords are a common target for credential-stuffing and brute-force attacks, especially for accounts without MFA enforced or for break-glass/service accounts that still use console passwords. Short minimum password lengths make it computationally feasible for attackers to brute-force or dictionary-attack passwords, especially when combined with leaked credential lists from other breaches (credential stuffing). A 14-character minimum substantially raises the cost of both offline and online guessing attacks and aligns with modern NIST/CIS guidance for password policies. Because this is an account-wide setting, a weak minimum length applies to every IAM user with console access, making it a single point of exposure across the whole account.

## How Checkov evaluates this
This is a Python check built on `BaseResourceValueCheck` for `aws_iam_account_password_policy`, inspecting the `minimum_password_length` attribute (expected value: `14`):
- If `minimum_password_length` is a Terraform variable reference that can't be statically resolved, the result is `UNKNOWN`.
- The value is coerced to an integer; if it is **not set** or is **less than 14**, the check **FAILS**.
- If `minimum_password_length` is **14 or greater**, the check **PASSES**.
- Note: because of the underlying logic (`not (length and length < 14)`), a resource that omits `minimum_password_length` entirely also **FAILS** (falls into the "not length" branch which negates to False → fails), so the attribute must be explicitly set to 14+.

## Non-compliant example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length = 8
  require_uppercase_characters = true
  require_numbers               = true
}
```

## Remediated example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_uppercase_characters = true
  require_lowercase_characters = true
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention       = 24
}
```

## Remediation steps
1. Set `minimum_password_length = 14` (or greater) on the `aws_iam_account_password_policy` resource.
2. Since this resource is a singleton per account, ensure only one such resource is defined/applied — conflicting definitions across multiple Terraform states will fight each other.
3. Pair the length requirement with complexity requirements (`require_uppercase_characters`, `require_numbers`, `require_symbols`) and password rotation/reuse settings for a complete policy.
4. Strongly consider requiring MFA for all IAM users and moving toward federated/SSO access instead of long-lived IAM user passwords, which reduces reliance on password policy alone.
5. Applying this change does not require resource replacement; it updates the account's existing password policy in place.
6. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/PasswordPolicyLength.py)
- [Terraform aws_iam_account_password_policy documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy)
