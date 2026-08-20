# CKV_ALI_24: Ensure RAM enforces MFA
## Severity
**LOW** (score: 2.0/10)

Failing to enforce MFA for RAM logins removes a critical second authentication factor, making accounts significantly easier to compromise via phishing or credential leaks alone.

## Summary
This check verifies that Alibaba Cloud RAM security preferences enforce multi-factor authentication (MFA) for user login.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `alicloud_ram_security_preference`

## Why it matters
Passwords alone — even strong, well-rotated ones — remain vulnerable to phishing, credential-stuffing (reused passwords leaked from unrelated breaches), keylogging malware, and social engineering. MFA requires a second, independent factor (typically a time-based one-time code from an authenticator app or hardware token) before a login succeeds, so a stolen or guessed password alone is no longer sufficient to compromise an account. Because RAM controls access to the entire Alibaba Cloud account and its resources, failing to enforce MFA account-wide leaves a single point of failure — one leaked password — capable of granting an attacker full account access.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` on `alicloud_ram_security_preference` with `missing_block_result=CheckResult.FAILED` (notably, unlike some other checks in this family, an absent resource/attribute is treated as non-compliant, not compliant):
- Inspects the `enforce_mfa_for_login` attribute.
- FAILS if the resource is missing entirely, or if `enforce_mfa_for_login` is unset/`false`.
- PASSES if `enforce_mfa_for_login = true`.

## Non-compliant example
```hcl
resource "alicloud_ram_security_preference" "example" {
  enforce_mfa_for_login = false   # <-- fails: MFA not enforced
}
```

## Remediated example
```hcl
resource "alicloud_ram_security_preference" "example" {
  enforce_mfa_for_login = true    # <-- fix: MFA required for all RAM logins
}
```

## Remediation steps
1. Ensure an `alicloud_ram_security_preference` resource exists in your Terraform configuration (there is normally a single account-wide instance of this resource).
2. Set `enforce_mfa_for_login = true`.
3. Roll this out with a communication plan — users without an MFA device enrolled may be locked out of console login until they enroll, so coordinate the enforcement date and provide enrollment instructions in advance.
4. Combine with a strong password policy (CKV_ALI_15/16/17/18/19/23) for defense in depth; MFA does not replace password hygiene, it supplements it.
5. Verify break-glass/emergency access procedures still work under MFA enforcement before rolling out broadly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/RAMSecurityEnforceMFA.py)
- [Alibaba Cloud RAM security preference resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_security_preference)
