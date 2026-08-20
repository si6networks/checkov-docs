# CKV_ALI_17: Ensure RAM password policy requires at least one lowercase letter
## Severity
**LOW** (score: 2.0/10)

Missing a lowercase-character requirement modestly reduces password entropy and brute-force resistance for RAM accounts, a minor weakening of an authentication control rather than a direct exposure.

## Summary
This check verifies that the Alibaba Cloud RAM account password policy requires passwords to contain at least one lowercase letter.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`

## Why it matters
Character-class diversity requirements (lowercase, uppercase, numbers, symbols) directly increase the entropy/search space an attacker must cover in offline or online brute-force and dictionary attacks against RAM user passwords. Omitting a lowercase-letter requirement allows weaker passwords (e.g., all-uppercase or numeric-only strings) that are more predictable and easier to crack, undermining the account's overall authentication security posture.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `require_lowercase_characters` attribute on `alicloud_ram_account_password_policy`:
- FAILS if `require_lowercase_characters` is unset or `false`.
- PASSES if `require_lowercase_characters = true`.

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = false   # <-- fails the check
  require_uppercase_characters = true
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
  require_lowercase_characters = true    # <-- fix: lowercase letter required
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  max_login_attempts             = 3
}
```

## Remediation steps
1. Locate the account's `alicloud_ram_account_password_policy` resource.
2. Set `require_lowercase_characters = true`.
3. Apply the change; existing passwords are unaffected until the user's next password change, at which point the new rule is enforced.
4. Pair with `require_uppercase_characters` (CKV_ALI_19), `require_symbols` (CKV_ALI_15), and a sufficient `minimum_password_length` for a complete complexity policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyLowercaseLetter.py)
- [Alibaba Cloud RAM account password policy resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy)
