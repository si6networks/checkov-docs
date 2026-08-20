# CKV_ALI_18: Ensure RAM password policy prevents password reuse
## Severity
**MEDIUM** (score: 5.0/10)

Allowing password reuse lets compromised or previously leaked passwords be recycled, moderately raising the odds of credential-based account takeover over time.

## Summary
This check verifies that the Alibaba Cloud RAM account password policy blocks users from reusing at least the last 24 passwords.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`

## Why it matters
Without reuse prevention, users forced to rotate passwords (see CKV_ALI_16) can simply cycle back to an old, possibly already-compromised or already-known password — defeating the purpose of expiration policies entirely. Preventing reuse of the last 24 passwords ensures that a forced rotation event meaningfully changes the credential and that a password leaked in the past cannot be silently reinstated by an unwitting or careless user.

## How Checkov evaluates this
Custom `scan_resource_conf` logic on `password_reuse_prevention`:
- If the key is present, its value is coerced to an integer.
- FAILS if the value is truthy and **less than** 24.
- PASSES if the value is `24` or greater (or effectively unset/falsy after coercion, per the `not (reuse and reuse < 24)` condition).
- If the key is absent entirely, the check FAILS (falls through to the final `return CheckResult.FAILED`).

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 5     # <-- fails: allows reuse after only 5 changes
  max_login_attempts             = 3
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
  password_reuse_prevention      = 24    # <-- fix: block reuse of last 24 passwords
  max_login_attempts             = 3
}
```

## Remediation steps
1. Locate the account's `alicloud_ram_account_password_policy` resource.
2. Set `password_reuse_prevention` to `24` (or higher).
3. Apply the change; this only takes effect on future password changes.
4. Combine with `max_password_age <= 90` (CKV_ALI_16) so rotation is both forced and meaningful.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyReuse.py)
- [Alibaba Cloud RAM account password policy resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy)
