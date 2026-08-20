# CKV2_OCI_1: Ensure administrator users are not associated with API keys

## Severity
**MEDIUM** (score: 5.0/10)

Attaching a long-lived, non-interactive API key to a full-Administrators account creates a standing credential that, if leaked, grants tenancy-wide admin access without needing MFA or the account password.

## Summary
This check ensures that Oracle Cloud Infrastructure (OCI) users who are members of the `Administrators` identity group do not have an `oci_identity_api_key` associated with their account, since API keys provide long-lived, non-interactive programmatic credentials that bypass typical MFA/session controls.

## Applicability
Terraform. Applies to the graph relationship between `oci_identity_group`, `oci_identity_user_group_membership`, `oci_identity_user`, and (transitively) `oci_identity_api_key` resources.

## Why it matters
API keys in OCI are static, long-lived credentials (an RSA key pair) used to sign API requests without requiring interactive login or MFA. If an account with full `Administrators` group privileges also has an API key attached, that key becomes a standing, un-rotatable-by-policy backdoor into the tenancy with admin-level access: if the private key is leaked (checked into a repo, exposed on a compromised workstation, or exfiltrated from a CI system), an attacker gains full administrative control of the OCI tenancy without ever needing the admin's password or a second factor. Best practice (and OCI's own security guidance) is that break-glass/admin accounts should be used only via the interactive console with MFA enforced, and any programmatic automation should use a dedicated, narrowly-scoped, non-administrator user or Instance Principal/Resource Principal auth instead.

## How Checkov evaluates this
Graph-based JSON policy (`AdministratorUserNotAssociatedWithAPIKey.json`). The check's `or` logic passes a given `oci_identity_user` resource if any of these are true:
1. The user is connected (via `oci_identity_user_group_membership`) to a group named exactly `Administrators`, AND that user has NO connection to any `oci_identity_api_key` resource.
2. The user is connected to a group whose `name` is NOT `Administrators` (i.e., non-admin users are exempt from this check entirely).
3. The user has no group membership connection at all.
It fails only for the case not covered above: a user that IS a member of the `Administrators` group AND IS connected to an `oci_identity_api_key` resource.

## Non-compliant example
```hcl
resource "oci_identity_group" "admins" {
  compartment_id = var.tenancy_ocid
  name           = "Administrators"
  description    = "Tenancy administrators"
}

resource "oci_identity_user" "admin_user" {
  compartment_id = var.tenancy_ocid
  name           = "jdoe-admin"
  description    = "Admin user"
  email          = "jdoe@example.com"
}

resource "oci_identity_user_group_membership" "admin_membership" {
  group_id = oci_identity_group.admins.id
  user_id  = oci_identity_user.admin_user.id
}

resource "oci_identity_api_key" "admin_key" {
  user_id   = oci_identity_user.admin_user.id
  key_value = file("admin_public_key.pem")
}
```

## Remediated example
```hcl
resource "oci_identity_group" "admins" {
  compartment_id = var.tenancy_ocid
  name           = "Administrators"
  description    = "Tenancy administrators"
}

resource "oci_identity_user" "admin_user" {
  compartment_id = var.tenancy_ocid
  name           = "jdoe-admin"
  description    = "Admin user - interactive console access only, MFA enforced"
  email          = "jdoe@example.com"
}

resource "oci_identity_user_group_membership" "admin_membership" {
  group_id = oci_identity_group.admins.id
  user_id  = oci_identity_user.admin_user.id
}

# No oci_identity_api_key resource for the admin user.
# Automation instead uses a dedicated, non-admin service user with a scoped policy:
resource "oci_identity_user" "automation_user" {
  compartment_id = var.tenancy_ocid
  name           = "ci-automation"
  description    = "Least-privilege automation user"
  email          = "ci-automation@example.com"
}

resource "oci_identity_api_key" "automation_key" {
  user_id   = oci_identity_user.automation_user.id
  key_value = file("automation_public_key.pem")
}
```

## Remediation steps
1. Identify all users in the `Administrators` group that also have an associated `oci_identity_api_key`.
2. Remove/rotate away those API keys (`oci_identity_api_key` resources) for admin-group users.
3. For any automation currently relying on the admin API key, create a dedicated non-admin user with an IAM policy scoped to exactly the permissions the automation needs, and issue the API key to that user instead.
4. Where possible, replace static API keys with OCI Instance Principals or Resource Principals for workloads running on OCI compute/functions, eliminating long-lived credentials entirely.
5. Enforce MFA on all `Administrators` group accounts and require console (not API-key) access for admin-level actions.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/oci/AdministratorUserNotAssociatedWithAPIKey.json
