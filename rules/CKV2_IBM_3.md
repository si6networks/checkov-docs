# CKV2_IBM_3: Ensure API key creation is restricted in account settings

## Severity
**MEDIUM** (score: 5.0/10)

Unrestricted platform API key creation lets any authorized user mint new long-lived credentials, an easy path to persistent, hard-to-audit privilege escalation across the account.

## Summary
This check ensures that IBM Cloud account-level IAM settings (`ibm_iam_account_settings`) have `restrict_create_platform_apikey` set to `RESTRICTED`, preventing arbitrary users from freely creating new platform API keys.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ibm_iam_account_settings`

This is a graph-based check (Checkov "graph check", defined as JSON) evaluating a single account-settings attribute.

## Why it matters
Platform API keys are long-lived credentials that can be used to authenticate to IBM Cloud APIs without interactive MFA, often with the same privileges as the identity that created them. If any user in the account can freely create new API keys, a compromised user account, a malicious insider, or a phished credential can be used to mint a durable, hard-to-detect backdoor credential that persists even if the original password is later rotated or MFA is enforced afterward. Restricting API key creation at the account level (`RESTRICTED`) means only specifically authorized administrators can create these keys, closing off a common privilege-persistence and credential-exfiltration technique.

## How Checkov evaluates this
The check requires:
1. `restrict_create_platform_apikey` attribute **exists** on `ibm_iam_account_settings`.
2. That attribute equals (case-insensitively) `"RESTRICTED"`.

The check **fails** if the attribute is missing, or set to any other value (e.g., `"NOT_RESTRICTED"` or `"NOT_SET"`).

## Non-compliant example
```hcl
resource "ibm_iam_account_settings" "settings" {
  restrict_create_platform_apikey = "NOT_RESTRICTED"
}
```

## Remediated example
```hcl
resource "ibm_iam_account_settings" "settings" {
  restrict_create_platform_apikey = "RESTRICTED"
}
```

## Remediation steps
1. Set `restrict_create_platform_apikey = "RESTRICTED"` on the account's `ibm_iam_account_settings` resource.
2. Identify which users/service IDs legitimately need to create API keys, and grant them the specific IAM permission (`iam-identity` API key creation) explicitly rather than leaving account-wide creation open.
3. Audit existing API keys in the account (`ibmcloud iam api-keys`) and rotate/revoke any that are unused, over-privileged, or unaccounted for before tightening this setting, so legitimate workflows aren't broken.
4. Communicate the change to teams that rely on self-service API key creation, since this is an account-wide setting affecting all users.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ibm/IBM_RestrictAPIkeyCreationInAccountSettings.json
- IBM Cloud docs: https://cloud.ibm.com/docs/account?topic=account-account_settings
