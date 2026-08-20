# CKV_ALI_23: Ensure Ram Account Password Policy Max Login Attempts not > 5
## Severity
**MEDIUM** (score: 5.0/10)

Allowing more than 5 failed login attempts before lockout weakens brute-force protection for RAM accounts, increasing the practical feasibility of password-guessing attacks.

## Summary
This check verifies that the Alibaba Cloud RAM account password policy caps failed login attempts at 5 or fewer before locking the account.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`

## Why it matters
Max login attempts is the account-lockout threshold used to defend against online password-guessing and brute-force attacks. A high (or unset/unbounded) threshold allows an attacker to make many more login attempts before being locked out, meaningfully increasing the odds of successfully guessing a weak or common password before the account is locked. Capping this at 5 or fewer attempts significantly narrows the window for brute-force attacks while still allowing for reasonable user typo tolerance.

## How Checkov evaluates this
Custom `scan_resource_conf` logic on `max_login_attempts`, with `missing_block_result=CheckResult.PASSED`:
- If `max_login_attempts` is not set at all, the check PASSES (Alibaba Cloud's platform default is assumed compliant).
- If set, the value is coerced to an integer; if it can't be coerced, the result is `UNKNOWN`.
- PASSES if the value is `<= 5`.
- FAILS if the value is greater than 5.

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  max_login_attempts             = 10   # <-- fails: too many attempts allowed before lockout
}
```

## Remediated example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  max_login_attempts             = 3    # <-- fix: locks out after a small number of failed attempts
}
```

## Remediation steps
1. Locate the account's `alicloud_ram_account_password_policy` resource.
2. Set `max_login_attempts` to a value of 5 or fewer (commonly `3`–`5`).
3. If you prefer to rely on the Alibaba Cloud platform default, you may omit the attribute entirely — Checkov treats a missing block as PASS — but explicitly setting a low value is more auditable and self-documenting.
4. Apply the change; this is an account-wide, in-place policy update with no resource replacement.
5. Provide users a clear self-service unlock/reset path so a low threshold doesn't create excessive support burden from legitimate lockouts.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyMaxLogin.py)
- [Alibaba Cloud RAM account password policy resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy)
