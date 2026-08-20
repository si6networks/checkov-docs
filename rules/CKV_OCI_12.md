# CKV_OCI_12: OCI IAM password policy - must contain Numeric characters
## Severity
**MEDIUM** (score: 5.0/10)

Not requiring numeric characters in the IAM password policy weakens password complexity, making credentials somewhat easier to guess or brute-force without disabling authentication outright.

## Summary
This check requires that an OCI `oci_identity_authentication_policy` resource's password policy mandates at least one numeric character (`is_numeric_characters_required = true`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `oci_identity_authentication_policy`
- **Check type:** resource (single attribute value check, nested under `password_policy` block index 0)

## Why it matters
Requiring numeric characters in passwords increases the character-space attackers must search when performing offline brute-force or dictionary attacks against stolen password hashes, and prevents users from choosing purely alphabetic (often dictionary-word-based) passwords that are far easier to guess or crack. Since OCI IAM credentials can be used to authenticate to the OCI Console and APIs — potentially granting access to compartments, resources, and administrative operations — a weak password complexity baseline undermines the security of every resource protected behind that identity.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects a nested attribute path:
- **Inspected key:** `password_policy/[0]/is_numeric_characters_required`
- **Expected value:** `True`
- **PASS:** the first `password_policy` block sets `is_numeric_characters_required = true`.
- **FAIL:** the attribute is `false`, or is not set within the `password_policy` block (including when no `password_policy` block is defined at all).

## Non-compliant example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length          = 12
    is_lowercase_characters_required = true
    is_uppercase_characters_required = true
    is_special_characters_required   = true
    is_numeric_characters_required   = false
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
    is_uppercase_characters_required = true
    is_special_characters_required   = true
    is_numeric_characters_required   = true
  }
}
```

## Remediation steps
1. Add or set `is_numeric_characters_required = true` inside the `password_policy` block of the `oci_identity_authentication_policy` resource.
2. Combine this with the companion checks (lowercase, uppercase, special-character requirements — CKV_OCI_11/13/14) to build a complete complexity policy.
3. Remember there is a single tenancy-wide authentication policy in OCI; the change affects all local IAM users and existing passwords that don't meet the new rule will require a reset on next change — plan the rollout accordingly.
4. Where feasible, pair local password policy hardening with MFA enforcement and/or federation to an external IdP for stronger overall authentication assurance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/IAMPasswordPolicyNumeric.py)
- [OCI Identity password policy documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingpasswordpolicy.htm)
