# CKV_OCI_18: OCI IAM password policy for local (non-federated) users has a minimum length of 14 characters

## Severity
**MEDIUM** (score: 5.0/10)

A password policy allowing shorter than 14 characters weakens resistance to brute-force and credential-stuffing attacks against local IAM users, though it does not disable authentication outright.

## Summary
This check ensures that the OCI IAM authentication policy (`oci_identity_authentication_policy`) enforces a minimum password length of at least 14 characters for local (non-federated) IAM users.

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_identity_authentication_policy`

## Why it matters
Password length is one of the strongest single predictors of resistance to offline brute-force and credential-stuffing attacks — each additional character exponentially increases the keyspace an attacker must search. Local (non-federated) IAM users in OCI authenticate directly against Oracle's IAM service with a password, and if the tenancy's password policy allows short passwords, users tend to choose weak, easily guessed, or reused passwords, increasing the risk of account takeover via brute force, credential stuffing (reused breached passwords), or password spraying. A 14-character minimum aligns with modern guidance (e.g., NIST SP 800-63B and CIS Benchmarks for OCI) that favor longer minimum lengths over complex character-composition rules, since length is generally more effective and more user-friendly than forced special-character requirements.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` that inspects the `password_policy` block on `oci_identity_authentication_policy`. The check logic is:
- If `password_policy` is absent entirely → FAILED.
- If present but `minimum_password_length` is absent → FAILED.
- If `minimum_password_length` is present and is an integer less than 14 → FAILED.
- Otherwise (an integer value of 14 or greater) → PASSED.

## Non-compliant example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length        = 8
    is_lowercase_characters_required = true
    is_uppercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
  }
}
```

## Remediated example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length          = 14
    is_lowercase_characters_required = true
    is_uppercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
  }
}
```

## Remediation steps
1. Ensure an `oci_identity_authentication_policy` resource exists for the tenancy — this is typically a single, tenancy-wide resource.
2. Set `minimum_password_length = 14` (or higher) inside the `password_policy` block.
3. Communicate the policy change to your users ahead of enforcement, since it can force password resets for existing local accounts that don't meet the new minimum.
4. Where possible, prefer federating users through an identity provider (SSO/SAML/OIDC) so this local password policy applies to a minimal set of break-glass/service accounts only.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/IAMPasswordLength.py)
