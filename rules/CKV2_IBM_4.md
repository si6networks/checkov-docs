# CKV2_IBM_4: Ensure Multi-Factor Authentication (MFA) is enabled at the account level

## Severity
**MEDIUM** (score: 5.0/10)

Disabling account-level MFA removes a critical control against credential-based takeover, making every user account reliant on password strength alone for authentication security.

## Summary
This check ensures that IBM Cloud account-level IAM settings (`ibm_iam_account_settings`) have the `mfa` attribute set to something other than `"None"`, meaning multi-factor authentication is required for users in the account.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ibm_iam_account_settings`

This is a graph-based check (Checkov "graph check", defined as JSON) evaluating a single account-settings attribute.

## Why it matters
Password-only authentication is vulnerable to phishing, credential stuffing (reusing leaked passwords from other breaches), and brute-force attacks. If an account does not enforce MFA, a single compromised password is sufficient for an attacker to gain full access to the IBM Cloud account — potentially including billing, IAM policy management, and every resource in the account. MFA adds a second, independent factor (e.g., a TOTP code, hardware key, or mobile authenticator) that dramatically raises the bar for account takeover, since the attacker would need to also compromise the victim's physical device or authenticator app.

## How Checkov evaluates this
The check requires:
1. The `mfa` attribute **exists** on `ibm_iam_account_settings`.
2. That attribute is **not equal** (case-insensitively) to `"None"`.

The check **fails** if `mfa` is missing, or explicitly set to `"NONE"`. Valid non-`None` values in IBM Cloud include options like `TOTP`, `TOTP4ALL`, `LEVEL1`, `LEVEL2`, `LEVEL3` (email-based, or hardware-key-based tiers depending on account type).

## Non-compliant example
```hcl
resource "ibm_iam_account_settings" "settings" {
  mfa = "NONE"
}
```

## Remediated example
```hcl
resource "ibm_iam_account_settings" "settings" {
  mfa = "TOTP4ALL"
}
```

## Remediation steps
1. Set the `mfa` attribute on `ibm_iam_account_settings` to an appropriate enforcement level (e.g., `TOTP4ALL` to require MFA for all users, or a `LEVEL*` value if your account uses IBMid-based tiered MFA).
2. Communicate the change to all account users in advance — enforcing MFA account-wide will require users without an authenticator configured to set one up before their next login.
3. Verify break-glass/emergency access procedures exist (e.g., a securely stored recovery credential) in case the primary MFA method becomes unavailable.
4. Combine with session timeout and IP allowlist settings (also configurable via `ibm_iam_account_settings`) for defense in depth.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ibm/IBM_EnableMFAatAccountLevel.json
- IBM Cloud docs: https://cloud.ibm.com/docs/account?topic=account-mfa
