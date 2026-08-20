# CKV_OCI_3: OCI Block Storage Block Volumes are not encrypted with a Customer Managed Key (CMK)

## Severity
**LOW** (score: 2.0/10)

Block volumes not encrypted with a customer-managed key reduce control over key rotation and revocation for potentially sensitive data at rest, increasing risk if the underlying storage or provider-managed keys are compromised.

## Summary
This check ensures that OCI Block Storage block volumes (`oci_core_volume`) specify a customer-managed KMS key for encryption rather than relying solely on Oracle's default (Oracle-managed) at-rest encryption key.

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_volume`

## Why it matters
OCI encrypts all block volumes at rest by default using an Oracle-managed key, but that default key is entirely controlled by Oracle: you cannot rotate it on your own schedule, restrict who can use it via your own IAM policies, revoke access to it independently of the volume, or produce an audit trail of key usage tied to your own KMS vault. Using a Customer Managed Key (CMK) via OCI Vault gives you control over key rotation, granular IAM policies on the key itself, the ability to instantly disable/revoke access (effectively "shredding" the volume's data) independent of deleting the volume, and centralized audit logging of key operations. For regulated workloads (PCI-DSS, HIPAA, FedRAMP) a customer-controlled key is frequently a hard compliance requirement, and its absence significantly weakens the tenant's ability to enforce cryptographic separation of duties and key lifecycle control.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `kms_key_id` attribute on `oci_core_volume`. The check passes if `kms_key_id` is set to any non-empty value; it fails if the attribute is missing, meaning the volume falls back to Oracle's default encryption key.

## Non-compliant example
```hcl
resource "oci_core_volume" "app_data" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = "app-data-volume"
  size_in_gbs         = 100
  # No kms_key_id - uses Oracle-managed encryption key by default
}
```

## Remediated example
```hcl
resource "oci_kms_key" "volume_cmk" {
  compartment_id = var.compartment_id
  display_name   = "app-data-volume-key"
  management_endpoint = var.kms_management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_core_volume" "app_data" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = "app-data-volume"
  size_in_gbs         = 100
  kms_key_id          = oci_kms_key.volume_cmk.id
}
```

## Remediation steps
1. Provision (or identify) an OCI Vault and a KMS master encryption key in the same region as the volume.
2. Grant the block storage service the necessary IAM policy to use the key (`allow service blockstorage to use keys in compartment <compartment>`).
3. Set `kms_key_id` on the `oci_core_volume` resource to the key's OCID.
4. Note: changing `kms_key_id` on an existing volume may require recreating the volume or performing a re-encryption operation depending on provider version — test in a non-production environment first, and plan for potential downtime/data migration.
5. Establish a key rotation policy on the vault key going forward.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/StorageBlockEncryption.py)
