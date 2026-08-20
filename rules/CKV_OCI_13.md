# CKV_OCI_13: OCI IAM password policy - must contain Special characters
## Severity
**MEDIUM** (score: 5.0/10)

Not requiring special characters in the IAM password policy weakens password complexity, making credentials somewhat easier to guess or brute-force without disabling authentication outright.

## Summary
This check requires that an OCI `oci_identity_authentication_policy` resource's password policy mandates at least one special character (`is_special_characters_required = true`).

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `oci_identity_authentication_policy`
- **Check type:** resource (single attribute value check, nested under `password_policy` block index 0)

## Why it matters
Special characters (symbols such as `!`, `@`, `#`, `$`) meaningfully increase the entropy of a password, which raises the computational cost of brute-force and dictionary attacks against stolen credential hashes. Without this requirement, users can create passwords built only from letters and digits, which are considerably faster to crack with modern GPU-based cracking tools and are more likely to overlap with common password lists used in credential-stuffing attacks. Because OCI IAM credentials gate access to the OCI Console and API for compartments and resources across the tenancy, a weak complexity baseline is a direct amplifier of account-takeover risk.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects a nested attribute path:
- **Inspected key:** `password_policy/[0]/is_special_characters_required`
- **Expected value:** `True`
- **PASS:** the first `password_policy` block sets `is_special_characters_required = true`.
- **FAIL:** the attribute is `false`, or is not set within the `password_policy` block (including when no `password_policy` block is defined at all).

## Non-compliant example
```hcl
resource "oci_identity_authentication_policy" "tenancy_policy" {
  compartment_id = var.tenancy_ocid

  password_policy {
    minimum_password_length          = 12
    is_lowercase_characters_required = true
    is_uppercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = false
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
    is_numeric_characters_required   = true
    is_special_characters_required   = true
  }
}
```

## Remediation steps
1. Add or set `is_special_characters_required = true` inside the `password_policy` block of the `oci_identity_authentication_policy` resource.
2. Combine this with the companion checks (lowercase, uppercase, numeric requirements — CKV_OCI_11/12/14) to enforce a full complexity policy.
3. Since there is only one tenancy-wide authentication policy, plan the rollout: existing users' current passwords remain valid until their next required change, so communicate the new requirement ahead of enforcement.
4. Consider combining stronger password complexity with mandatory MFA for all local IAM users as defense in depth.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/IAMPasswordPolicySpecialCharacters.py)
- [OCI Identity password policy documentation](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingpasswordpolicy.htm)
