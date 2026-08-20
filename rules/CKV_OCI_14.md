# CKV_OCI_14: OCI IAM password policy - must contain Uppercase characters
## Severity
**MEDIUM** (score: 5.0/10)

Not requiring uppercase characters in the IAM password policy weakens password complexity, making credentials somewhat easier to guess or brute-force without disabling authentication outright.

## Summary
This check requires that an OCI `oci_identity_authentication_policy` resource's password policy mandates at least one uppercase character (`is_uppercase_characters_required = true`).

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `oci_identity_authentication_policy`
- **Check type:** resource (single attribute value check, nested under `password_policy` block index 0)

## Why it matters
Requiring a mix of uppercase and lowercase letters (in addition to numbers and symbols) increases password entropy and makes brute-force or dictionary-based cracking attacks meaningfully more expensive. Without this requirement, all-lowercase passwords are permitted, which are more predictable and overlap heavily with common wordlists used in credential-stuffing and password-spraying attacks. Because OCI IAM local credentials authenticate users to the OCI Console and API — surfaces that can grant access to compartments and resources tenancy-wide — weak complexity requirements directly increase the likelihood of successful account compromise.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects a nested attribute path (note: the underlying class is internally still named `IAMPasswordPolicySpecialCharacters` in source but is configured for the uppercase key/id):
- **Inspected key:** `password_policy/[0]/is_uppercase_characters_required`
- **Expected value:** `True`
- **PASS:** the first `password_policy` block sets `is_uppercase_characters_required = true`.
- **FAIL:** the attribute is `false`, or is not set within the `password_policy` block (including when no `password_policy` block is defined at all).

## Non-compliant example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length          = 12
    is_lowercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
    is_uppercase_characters_required = false
  }
}
```

## Remediated example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length          = 12
    is_lowercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
    is_uppercase_characters_required = true
  }
}
```

## Remediation steps
1. Add or set `is_uppercase_characters_required = true` inside the `password_policy` block of the `oci_identity_authentication_policy` resource.
2. Combine this with the companion checks (lowercase, numeric, special-character requirements — CKV_OCI_11/12/13) for a complete complexity policy.
3. Since OCI has one tenancy-wide authentication policy, coordinate the rollout with affected local IAM users, as existing passwords remain valid until their next scheduled change.
4. Consider federating to an external identity provider with its own strong password/MFA policy for users who need more than baseline local-account protection.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/IAMPasswordPolicyUpperCase.py)
- [OCI Identity password policy documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingpasswordpolicy.htm)
