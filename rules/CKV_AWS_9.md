# CKV_AWS_9: Ensure IAM password policy expires passwords within 90 days or less

## Severity
**LOW** (score: 2.0/10)

Allowing passwords to remain valid beyond 90 days weakens the password-rotation control, increasing the window in which a compromised credential remains usable, but it does not by itself grant access.

## Summary
This check fails when an AWS account's IAM password policy either has no maximum password age configured, or sets `max_password_age` to a value greater than 90 days (or to `0`/an invalid value).

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_iam_account_password_policy` resource — inspects the `max_password_age` argument.

## Why it matters
IAM users (as opposed to federated/SSO identities) authenticate with long-lived passwords. Without an enforced expiration policy, a compromised or leaked password (via phishing, credential-stuffing lists, accidental commit, shoulder-surfing, etc.) remains valid indefinitely, giving an attacker unlimited time to exploit it before rotation forces a change. Enforcing a maximum password age bounds the exposure window for any single compromised credential and is a baseline control in most compliance frameworks (CIS AWS Foundations Benchmark, PCI-DSS, NIST 800-53) specifically for this reason — it does not prevent an initial compromise but limits how long it can be leveraged.

## How Checkov evaluates this
The Terraform check reads the `max_password_age` key from the `aws_iam_account_password_policy` resource:
- If the key is missing entirely → **FAILED**.
- If the value is a Terraform variable/expression that cannot be statically resolved → **UNKNOWN**.
- The value is coerced to an integer; if it is greater than `0` and less than or equal to `90` → **PASSED**.
- Any other case (value is `0`, negative, non-numeric, or greater than `90`) → **FAILED**.

## Non-compliant example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                  = true
  require_numbers                  = true
  max_password_age                = 365   # far too long
}
```

## Remediated example
```hcl
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                  = true
  require_numbers                  = true
  max_password_age                = 90    # expires within Checkov's threshold
  password_reuse_prevention       = 24
}
```

## Remediation steps
1. Add or update the `aws_iam_account_password_policy` resource in the account (this is a singleton — one policy per AWS account) with `max_password_age` set to a value between 1 and 90.
2. Pair expiration with `password_reuse_prevention` so users cannot simply cycle back to the same password.
3. Prefer eliminating long-lived IAM user passwords altogether where possible — use AWS IAM Identity Center (SSO) or federated roles with short-lived credentials instead of console passwords, which sidesteps this class of risk entirely.
4. If `max_password_age` must be a computed/variable value for legitimate reasons (e.g., pulled from an org policy module), be aware Checkov will report `UNKNOWN` rather than pass/fail — verify the resolved value out-of-band.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/PasswordPolicyExpiration.py
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
- Terraform docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy
