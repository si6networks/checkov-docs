# CKV_ALI_19: Ensure RAM password policy requires at least one uppercase letter
## Severity
**MEDIUM** (score: 5.0/10)

Missing an uppercase-character requirement modestly reduces password entropy and brute-force resistance for RAM accounts, a minor weakening of an authentication control rather than a direct exposure.

## Summary
This check verifies that the Alibaba Cloud RAM account password policy requires passwords to contain at least one uppercase letter.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`

## Why it matters
As with the lowercase-letter requirement (CKV_ALI_17), requiring an uppercase character increases password entropy and closes off predictable password patterns (e.g., all-lowercase dictionary words or all-numeric strings) that are disproportionately represented in leaked-password and brute-force wordlists. Skipping this requirement weakens the account's baseline password strength for every RAM user.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `require_uppercase_characters` attribute on `alicloud_ram_account_password_policy`:
- FAILS if `require_uppercase_characters` is unset or `false`.
- PASSES if `require_uppercase_characters = true`.

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = false   # <-- fails the check
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  max_login_attempts             = 3
}
```

## Remediated example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = true    # <-- fix: uppercase letter required
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  max_login_attempts             = 3
}
```

## Remediation steps
1. Locate the account's `alicloud_ram_account_password_policy` resource.
2. Set `require_uppercase_characters = true`.
3. Apply the change; enforcement begins at each user's next password change.
4. Pair with `require_lowercase_characters` (CKV_ALI_17), `require_symbols` (CKV_ALI_15), `require_numbers`, and adequate `minimum_password_length` for a full complexity baseline.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyUppcaseLetter.py)
- [Alibaba Cloud RAM account password policy resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy)
