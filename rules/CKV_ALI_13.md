# CKV_ALI_13: Ensure RAM password policy requires minimum length of 14 or greater

## Severity
**LOW** (score: 2.0/10)

A minimum password length below 14 characters weakens resistance to offline brute-force/credential-stuffing attacks against RAM accounts, though it does not disable authentication outright.

## Summary
This check verifies that an Alibaba Cloud RAM account password policy enforces a minimum password length of at least 14 characters, reducing the risk of weak, easily brute-forced credentials.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`
- **Category:** IAM

## Why it matters
Password length is one of the strongest determinants of resistance to brute-force and credential-stuffing attacks. A RAM (Resource Access Management) account password policy that permits short passwords weakens the primary authentication control protecting an Alibaba Cloud account and all resources under it. Enforcing a minimum length of 14 characters aligns with common security baselines (e.g., CIS-style guidance) for cloud IAM password policies.

## How Checkov evaluates this
The check (`PasswordPolicyLength` in `checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyLength.py`) extends `BaseResourceValueCheck` and inspects the `minimum_password_length` attribute of `alicloud_ram_account_password_policy` resources:

- It reads the `minimum_password_length` key from the resource configuration.
- If the value is a Terraform variable reference (not a literal), the result is `UNKNOWN` (cannot be statically evaluated).
- Otherwise, the value is coerced to an integer.
- The check **passes** only if the length is set and is **not** less than 14 (i.e., `length >= 14`).
- If the key is missing entirely, or the value is less than 14, the check **fails**.

Effectively: `minimum_password_length` must be explicitly configured to `14` or higher.

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "this" {
  minimum_password_length      = 8
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
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
2. Set (or add, if missing) the `minimum_password_length` attribute to `14` or a higher value.
3. Avoid deriving `minimum_password_length` from an unresolved Terraform variable without a safe default, since Checkov cannot statically verify variable-driven values and will report `UNKNOWN`.
4. Re-run `checkov` against the configuration to confirm the check now passes.
5. Apply the change with `terraform plan`/`terraform apply` and confirm the account-level RAM password policy reflects the new minimum length.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyLength.py)
