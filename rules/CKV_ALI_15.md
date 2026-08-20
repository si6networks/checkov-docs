# CKV_ALI_15: Ensure RAM password policy requires at least one symbol
## Severity
**LOW** (score: 2.0/10)

A password policy that omits a symbol requirement weakens brute-force resistance for RAM accounts but is only one layer of a broader authentication control, not a standalone exploitable exposure.

## Summary
This check verifies that the Alibaba Cloud RAM account password policy requires passwords to contain at least one symbol/special character.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`

## Why it matters
The RAM (Resource Access Management) account password policy governs the complexity requirements for every human login password in the Alibaba Cloud account. Requiring a symbol increases the character space an attacker must search when brute-forcing or dictionary-attacking a password, and it defeats the most common weak-password patterns (dictionary words, names, simple digit substitutions) that omit special characters. Without this requirement, users can set passwords like `Password1` that pass length/case rules but remain highly guessable, materially weakening account-takeover resistance for every RAM user and the account root.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `require_symbols` attribute on `alicloud_ram_account_password_policy`:
- If `require_symbols` is not set (or set to `false`), the check FAILS (the base class's default expected value for a boolean-style key is `true`).
- If `require_symbols = true`, the check PASSES.

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols                = false   # <-- fails the check
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
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols                = true    # <-- fix: at least one symbol required
  max_password_age               = 90
  password_reuse_prevention      = 24
  max_login_attempts             = 3
}
```

## Remediation steps
1. Locate the account's `alicloud_ram_account_password_policy` resource (there should be exactly one per account, since it is account-wide).
2. Set `require_symbols = true`.
3. Apply the change — this only affects password policy enforcement for future password changes; existing sessions are unaffected but users will be prompted to update non-compliant passwords at next change.
4. Consider pairing this with `require_lowercase_characters`, `require_uppercase_characters`, `require_numbers`, a strong `minimum_password_length`, and MFA enforcement (see CKV_ALI_24) for defense in depth.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicySymbol.py)
- [Alibaba Cloud RAM account password policy resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy)
