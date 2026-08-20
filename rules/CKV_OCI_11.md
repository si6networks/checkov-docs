# CKV_OCI_11: OCI IAM password policy - must contain lower case
## Severity
**MEDIUM** (score: 5.0/10)

Not requiring lowercase characters in the IAM password policy weakens password complexity, making credentials somewhat easier to guess or brute-force without disabling authentication outright.

## Summary
This check requires that an OCI `oci_identity_authentication_policy` resource's password policy mandates at least one lowercase character (`is_lowercase_characters_required = true`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `oci_identity_authentication_policy`
- **Check type:** resource (single attribute value check, nested under `password_policy` block index 0)

## Why it matters
Password complexity requirements exist to raise the cost of offline and online password-guessing attacks (brute force, dictionary attacks, credential-stuffing with leaked password lists). A policy that does not require lowercase characters allows users to choose weaker passwords (e.g., all-uppercase or all-numeric strings), shrinking the effective character-space an attacker must search and making automated cracking tools more effective. IAM credentials in OCI can grant access to compartments, resources, and administrative actions across the tenancy, so weak password policy is a foundational identity risk that undermines every other control built on top of authenticated access.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects a nested attribute path:
- **Inspected key:** `password_policy/[0]/is_lowercase_characters_required`
- **Expected value:** `True`
- **PASS:** the first `password_policy` block sets `is_lowercase_characters_required = true`.
- **FAIL:** the attribute is `false`, or is not set within the `password_policy` block (including when no `password_policy` block is defined at all).

## Non-compliant example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length          = 12
    is_uppercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
    is_lowercase_characters_required = false
  }
}
```

## Remediated example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length          = 12
    is_uppercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
    is_lowercase_characters_required = true
  }
}
```

## Remediation steps
1. Add or set `is_lowercase_characters_required = true` inside the `password_policy` block of the `oci_identity_authentication_policy` resource.
2. Combine this with the companion checks (uppercase, numeric, special-character requirements — CKV_OCI_12/13/14) for a complete complexity policy, and set an adequate `minimum_password_length`.
3. Note there is only one authentication policy per tenancy in OCI; changes apply tenancy-wide and affect all local IAM users, so coordinate the change and communicate the new requirements to users before enforcement, since existing passwords not meeting the new policy will need to be reset at next change.
4. Prefer federated identity (SSO/IdP) with strong MFA over local IAM passwords where possible, treating password policy as a baseline for any remaining local accounts.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/IAMPasswordPolicyLowerCase.py)
- [OCI Identity password policy documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingpasswordpolicy.htm)
