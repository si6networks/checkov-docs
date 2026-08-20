# CKV_OCI_15: Ensure OCI File System is Encrypted with a customer Managed Key
## Severity
**LOW** (score: 2.0/10)

An OCI File System without a customer-managed encryption key relies solely on provider-managed defaults for data at rest, reducing control over encryption and key management for potentially sensitive shared file data.

## Summary
This check requires that an OCI `oci_file_storage_file_system` resource specifies a `kms_key_id`, meaning the file system is encrypted using a customer-managed key (CMK) from OCI Vault rather than relying solely on the provider's default (Oracle-managed) encryption key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `oci_file_storage_file_system`
- **Check type:** resource (attribute-presence check using `ANY_VALUE`)

## Why it matters
All OCI File Storage file systems are encrypted at rest by default using an Oracle-managed key, but that default gives the customer no control over the key's lifecycle: it cannot be independently rotated on the customer's schedule, disabled to immediately revoke access to data (a "crypto-shred" capability), or subjected to the customer's own access policies and audit logging. Using a customer-managed key from OCI Vault gives the data owner direct control over key rotation, the ability to instantly disable/revoke the key (rendering all data on the file system unreadable) in response to a suspected compromise, and a clear audit trail of every key-use event — all of which are frequently required by compliance regimes (PCI-DSS, HIPAA, FedRAMP) for regulated or sensitive data. Omitting a customer-managed key means these controls are unavailable, which is a meaningful gap for shared or regulated file storage.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` using the special `ANY_VALUE` sentinel as the expected value for the `kms_key_id` attribute:
- **Inspected key:** `kms_key_id`
- **Expected value:** `ANY_VALUE` (any non-empty value satisfies the check)
- **PASS:** `kms_key_id` is set to any value (i.e., a Vault master encryption key OCID is referenced).
- **FAIL:** `kms_key_id` is absent or empty, meaning the file system relies on Oracle's default-managed encryption key rather than a customer-managed one.

## Non-compliant example
```hcl
resource "oci_file_storage_file_system" "app_fs" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  display_name        = "app-file-system"
}
```

## Remediated example
```hcl
resource "oci_kms_key" "fs_cmk" {
  compartment_id = var.compartment_ocid
  display_name   = "app-fs-key"
  key_shape {
    algorithm = "AES"
    length    = 32
  }
  management_endpoint = var.kms_management_endpoint
}

resource "oci_file_storage_file_system" "app_fs" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  display_name        = "app-file-system"
  kms_key_id          = oci_kms_key.fs_cmk.id
}
```

## Remediation steps
1. Provision (or reference an existing) OCI Vault Master Encryption Key (`oci_kms_key`) in the appropriate compartment.
2. Set `kms_key_id` on the `oci_file_storage_file_system` resource to that key's OCID.
3. Note that changing the KMS key on an existing file system may not be a simple in-place update — verify whether your OCI Terraform provider version supports updating `kms_key_id` in place or whether it requires re-creating the file system (which would require a data migration).
4. Establish a key rotation and access policy for the Vault key (via IAM policies scoping who can use/manage it), and enable Vault audit logging so key usage is tracked separately from file system access.
5. Document a key-revocation runbook so the team knows how to disable the key quickly if the file system's data is ever suspected to be compromised.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/FileSystemEncryption.py)
- [OCI File Storage encryption documentation](https://docs.oracle.com/en-us/iaas/Content/File/Tasks/using-your-own-encryption-keys.htm)
