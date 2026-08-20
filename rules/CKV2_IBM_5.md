# CKV2_IBM_5: Ensure Service ID creation is restricted in account settings

## Severity
**MEDIUM** (score: 5.0/10)

Unrestricted service ID creation allows proliferation of non-human identities that can be granted access and are often under-monitored, increasing the account's privilege-escalation and persistence surface.

## Summary
This check ensures that IBM Cloud account-level IAM settings (`ibm_iam_account_settings`) have `restrict_create_service_id` set to `RESTRICTED`, preventing arbitrary users from freely creating new Service IDs.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `ibm_iam_account_settings`

This is a graph-based check (Checkov "graph check", defined as JSON) evaluating a single account-settings attribute.

## Why it matters
A Service ID is an identity used by applications or automated processes (rather than a human user) to authenticate to IBM Cloud, and can be granted IAM policies just like a regular user. If any user in the account is free to create Service IDs, a compromised account or malicious insider could create a new Service ID, grant it broad permissions, generate an API key for it, and use it as a persistent, less-visible backdoor identity — one that doesn't show up in typical user-account reviews and doesn't require MFA on subsequent use. Restricting Service ID creation (`RESTRICTED`) ensures only explicitly authorized administrators can mint these non-human identities, closing off a significant privilege-persistence vector.

## How Checkov evaluates this
The check requires:
1. The `restrict_create_service_id` attribute **exists** on `ibm_iam_account_settings`.
2. That attribute equals (case-insensitively) `"RESTRICTED"`.

The check **fails** if the attribute is missing, or set to any other value (e.g., `"NOT_RESTRICTED"` or `"NOT_SET"`).

## Non-compliant example
```hcl
resource "ibm_iam_account_settings" "settings" {
  restrict_create_service_id = "NOT_RESTRICTED"
}
```

## Remediated example
```hcl
resource "ibm_iam_account_settings" "settings" {
  restrict_create_service_id = "RESTRICTED"
}
```

## Remediation steps
1. Set `restrict_create_service_id = "RESTRICTED"` on the account's `ibm_iam_account_settings` resource.
2. Identify teams/pipelines that legitimately need to create Service IDs (e.g., CI/CD automation, integration accounts) and grant the specific IAM permission to create Service IDs explicitly to those principals, rather than leaving account-wide creation open.
3. Audit existing Service IDs in the account (`ibmcloud iam service-ids`) for orphaned or over-privileged identities before tightening this setting.
4. Pair this with restricting API key creation (see CKV2_IBM_3) since Service IDs are frequently paired with API keys for automation.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/ibm/IBM_RestrictServiceIDCreationInAccountSettings.json
- IBM Cloud docs: https://cloud.ibm.com/docs/account?topic=account-account_settings
