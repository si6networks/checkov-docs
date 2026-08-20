# CKV2_GCP_23: Ensure Document AI Warehouse Location is configured to use a Customer Managed Key (CMK)
## Severity
**MEDIUM** (score: 5.0/10)

A Document AI Warehouse Location without a CMK relies on Google-managed encryption, leaving reduced key-management control over potentially sensitive stored documents rather than an unencrypted or exposed dataset.

## Summary
This check ensures that a Document AI Warehouse Location resource references a customer-managed KMS key (`kms_key`) rather than relying solely on Google-managed default encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_document_ai_warehouse_location`

## Why it matters
Document AI Warehouse stores structured/unstructured document data, metadata, and search indexes — often derived from the same sensitive source documents (contracts, financial records, personal identification) processed by Document AI. As a persistent storage/indexing layer, it represents a long-lived, high-value data store. Relying only on Google-managed encryption means the organization has no independent mechanism to revoke access to that data (e.g., in an offboarding, breach-containment, or data-retention-expiry scenario) without deleting the underlying resource. Configuring a customer-managed key gives the data owner cryptographic control, supports compliance requirements for data-at-rest key ownership, and allows centralized key rotation and auditing via Cloud KMS/Cloud Audit Logs.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_document_ai_warehouse_location`:
- **PASS** if the `kms_key` attribute exists (is set).
- **FAIL** if `kms_key` is absent.

## Non-compliant example
```hcl
resource "google_document_ai_warehouse_location" "warehouse" {
  location   = "us"
  project_number = "123456789012"
  # no kms_key -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_document_ai_warehouse_location" "warehouse" {
  location       = "us"
  project_number = "123456789012"
  kms_key        = google_kms_crypto_key.warehouse_key.id
}

resource "google_kms_crypto_key" "warehouse_key" {
  name     = "docai-warehouse-key"
  key_ring = google_kms_key_ring.warehouse_ring.id
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in a location compatible with the Document AI Warehouse Location.
2. Grant the Document AI Warehouse service agent the appropriate `roles/cloudkms.cryptoKeyEncrypterDecrypter` permission on the key.
3. Set the `kms_key` attribute on the `google_document_ai_warehouse_location` resource.
4. CMEK configuration for a warehouse location is generally set at initialization time; changing it afterward is unlikely to be supported without recreating the resource.
5. Confirm current CMEK availability/regional support for Document AI Warehouse in GCP documentation, since it can be a newer/limited-availability feature.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPDocumentAIWarehouseLocationEncryptedWithCMK.json
- GCP docs: https://cloud.google.com/document-ai-warehouse/docs
