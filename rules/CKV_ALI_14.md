# CKV_ALI_14: Ensure RAM password policy requires at least one number

## Severity
**MEDIUM** (score: 5.0/10)

Not requiring numeric characters in RAM account passwords modestly reduces password complexity and search-space, a weak-but-not-absent control gap rather than a disabled authentication mechanism.

## Summary
This check verifies that an Alibaba Cloud RAM account password policy requires at least one numeric character in user passwords, increasing password complexity and resistance to guessing attacks.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`
- **Category:** IAM

## Why it matters
Password complexity requirements (mixing letters, numbers, and symbols) meaningfully increase the keyspace an attacker must search when attempting to brute-force or guess credentials. Omitting a numeric-character requirement from the account-wide RAM password policy allows users to set weaker, purely alphabetic passwords, undermining the account's authentication posture — especially in combination with other weak settings such as short minimum length (see CKV_ALI_13).

## How Checkov evaluates this
The check (`PasswordPolicyNumber` in `checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyNumber.py`) extends `BaseResourceValueCheck` and inspects the `require_numbers` attribute of `alicloud_ram_account_password_policy` resources:

- `get_inspected_key()` returns `require_numbers`.
- No custom `get_expected_value()` is defined, so the base class's default expected value (`True`) applies.
- Checkov reads the `require_numbers` attribute from the resource configuration and compares it against the expected value of `True`.
- The check **passes** only when `require_numbers` is explicitly set to `true`.
- If `require_numbers` is missing or set to `false`, the check **fails**.

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "this" {
  minimum_password_length      = 14
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = false
  require_symbols              = true
}
```

## Remediated example
```hcl
resource "alicloud_ram_account_password_policy" "this" {
  minimum_password_length      = 14
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
}
```

## Remediation steps
1. Locate the `alicloud_ram_account_password_policy` resource block(s) in your Terraform configuration.
2. Set (or add, if missing) the `require_numbers` attribute to `true`.
3. Review other password complexity attributes (`require_lowercase_characters`, `require_uppercase_characters`, `require_symbols`, `minimum_password_length`) at the same time to ensure a comprehensive, strong password policy.
4. Re-run `checkov` against the configuration to confirm the check now passes.
5. Apply the change with `terraform plan`/`terraform apply` and confirm the account-level RAM password policy now requires numeric characters.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyNumber.py)
