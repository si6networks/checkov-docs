# CKV_OCI_9: Ensure OCI Object Storage is encrypted with Customer Managed Key

## Severity
**LOW** (score: 2.0/10)

Object storage buckets not encrypted with a customer-managed key limit control over encryption key lifecycle for potentially sensitive stored objects, raising risk in the event of underlying key or storage compromise.

## Summary
This check ensures that an OCI Object Storage bucket (`oci_objectstorage_bucket`) is encrypted with a customer-managed KMS key rather than Oracle's default at-rest encryption key.

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_objectstorage_bucket`

## Why it matters
All OCI Object Storage buckets are encrypted at rest by default, but with an Oracle-managed key that you cannot rotate, restrict access to via your own IAM policy, or independently revoke. Using a Customer Managed Key (CMK) from OCI Vault gives your organization exclusive control over the key lifecycle: you can rotate it on your own schedule, apply granular IAM policies restricting which principals/services may use the key, produce audit logs of every key-use event, and — critically — instantly render the bucket's contents unreadable by disabling or deleting the key, independent of the storage layer itself. For data classified as sensitive (PII, financial records, health data), a customer-controlled encryption key is often a mandatory control under compliance frameworks (PCI-DSS, HIPAA, GDPR) because it enforces separation of duties between the cloud provider and the data owner.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `kms_key_id` attribute on `oci_objectstorage_bucket`. The check passes if `kms_key_id` is set to any non-empty value (`ANY_VALUE`); it fails if the attribute is absent, meaning the bucket relies on Oracle's default encryption key.

## Non-compliant example
```hcl
resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id = var.compartment_id
  namespace      = var.object_storage_namespace
  name           = "app-artifacts"
  # No kms_key_id - uses Oracle-managed encryption key by default
}
```

## Remediated example
```hcl
resource "oci_kms_key" "bucket_cmk" {
  compartment_id      = var.compartment_id
  display_name        = "app-bucket-key"
  management_endpoint = var.kms_management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_objectstorage_bucket" "app_bucket" {
  compartment_id = var.compartment_id
  namespace      = var.object_storage_namespace
  name           = "app-artifacts"
  kms_key_id     = oci_kms_key.bucket_cmk.id
}
```

## Remediation steps
1. Provision an OCI Vault and KMS master encryption key (in the same region as the bucket).
2. Grant the Object Storage service IAM policy to use the key (`allow service objectstorage-<region> to use keys in compartment <compartment>`).
3. Set `kms_key_id` on the `oci_objectstorage_bucket` resource to the key's OCID.
4. Applying this to an existing bucket re-encrypts newly written objects with the CMK going forward — confirm whether you need to re-upload/rewrite existing objects to bring them under the new key, depending on your compliance requirements.
5. Establish a key rotation schedule and monitor key usage via Audit logs.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/ObjectStorageEncryption.py)
