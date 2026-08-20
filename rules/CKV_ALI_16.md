# CKV_ALI_16: Ensure RAM password policy expires passwords within 90 days or less
## Severity
**LOW** (score: 2.0/10)

Passwords that never expire (or expire too infrequently) increase the window in which a stolen credential remains valid, a moderate risk mitigated by other controls like MFA.

## Summary
This check verifies that the Alibaba Cloud RAM account password policy forces password rotation at least every 90 days.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_account_password_policy`

## Why it matters
Without a maximum password age, credentials can remain valid indefinitely, even after being exposed in a phishing attack, leaked in a breach dump, written to a sticky note, or shared insecurely between employees. A bounded expiration window limits the useful lifetime of a compromised credential and forces periodic re-authentication of user identity through the password-reset flow. 90 days is a widely used compliance baseline (e.g., PCI-DSS historically required 90-day rotation) and this check encodes that expectation directly against the account's RAM policy.

## How Checkov evaluates this
Custom `scan_resource_conf` logic on the `max_password_age` attribute:
- If `max_password_age` is a Terraform variable reference, the result is `UNKNOWN`.
- Otherwise the value is coerced to an integer.
- PASS only if `max_password_age` is set and `0 < max_password_age <= 90`.
- Any other case (unset, `0`, negative, or greater than 90) FAILS.

## Non-compliant example
```hcl
resource "alicloud_ram_account_password_policy" "example" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers               = true
  require_symbols                = true
  max_password_age               = 365   # <-- fails: passwords never forced to rotate within 90 days
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
  require_symbols                = true
  max_password_age               = 90    # <-- fix: expire passwords within 90 days
  password_reuse_prevention      = 24
  max_login_attempts             = 3
}
```

## Remediation steps
1. Locate the account's `alicloud_ram_account_password_policy` resource.
2. Set `max_password_age` to a value between 1 and 90 (inclusive) — commonly `90`.
3. Avoid deriving `max_password_age` from an unresolved Terraform variable in code that Checkov statically scans, or the check will report `UNKNOWN` instead of a definitive PASS.
4. Apply the change; this is account-wide and only affects when existing users are prompted to change their password, no resource replacement occurs.
5. Communicate the new rotation requirement to RAM users so they aren't caught off guard by a forced password change.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMPasswordPolicyExpiration.py)
- [Alibaba Cloud RAM account password policy resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy)
