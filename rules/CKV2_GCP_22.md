# CKV2_GCP_22: Ensure Document AI Processors are encrypted with a Customer Managed Key (CMK)
## Severity
**MEDIUM** (score: 5.0/10)

Document AI Processors without a CMK still get default Google-managed encryption, so the risk is reduced customer control over key lifecycle for processed document data rather than a direct exposure path.

## Summary
This check ensures that Document AI Processor resources reference a customer-managed KMS key (`kms_key_name`) instead of relying only on Google-managed default encryption.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_document_ai_processor`

## Why it matters
Document AI processors ingest and process potentially sensitive documents (invoices, contracts, IDs, medical records, forms containing PII). Data processed and stored by these processors is encrypted at rest by default with Google-managed keys, which is adequate for baseline protection but does not give the data owner independent control over the encryption key. Without CMEK, the organization cannot enforce its own key rotation policy, cannot cryptographically "shred" data by revoking key access, and cannot satisfy compliance regimes (e.g., financial services, healthcare) that require customer control over encryption keys used for regulated data. Given the sensitive nature of documents typically routed through Document AI, using a customer-managed key is an important defense-in-depth and compliance control.

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_document_ai_processor`:
- **PASS** if the `kms_key_name` attribute exists (is set to any value).
- **FAIL** if `kms_key_name` is absent.

## Non-compliant example
```hcl
resource "google_document_ai_processor" "processor" {
  location     = "us"
  display_name = "invoice-processor"
  type         = "INVOICE_PROCESSOR"
  # no kms_key_name -> uses Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_document_ai_processor" "processor" {
  location     = "us"
  display_name = "invoice-processor"
  type         = "INVOICE_PROCESSOR"
  kms_key_name = google_kms_crypto_key.docai_key.id
}

resource "google_kms_crypto_key" "docai_key" {
  name     = "docai-processor-key"
  key_ring = google_kms_key_ring.docai_ring.id
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same location as the Document AI processor (Document AI CMEK support requires matching regions).
2. Grant the Document AI service agent the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on the key.
3. Set `kms_key_name` on the `google_document_ai_processor` resource to the key's resource ID.
4. CMEK for Document AI processors typically must be configured at processor creation time; changing it on an existing processor generally requires creating a new processor.
5. Confirm the specific Document AI processor type supports CMEK — availability can vary by processor type/region; check current GCP documentation before relying on this for a given processor.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPDocumentAIProcessorEncryptedWithCMK.json
- GCP docs: https://cloud.google.com/document-ai/docs/cmek
