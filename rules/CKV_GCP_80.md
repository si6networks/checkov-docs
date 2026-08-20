# CKV_GCP_80: Ensure Big Query Tables are encrypted with Customer Supplied/Managed Encryption Keys (CMEK)
## Severity
**LOW** (score: 2.0/10)

BigQuery tables remain encrypted at rest under Google-managed keys without CMEK; the gap is loss of independent key rotation/revocation control, not the absence of encryption itself.

## Summary
This check ensures a `google_bigquery_table` is configured with a customer-managed KMS key for encryption, rather than relying solely on Google's default encryption-at-rest.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_bigquery_table`

## Why it matters
All BigQuery data is encrypted at rest by default using Google-managed keys, but with Google-managed keys the organization has no control over key rotation policy, no ability to revoke access to the underlying key independent of GCP IAM, and no separation of duties between the cloud provider and the data owner. For data subject to compliance regimes requiring demonstrable customer control over encryption keys (e.g., certain regulatory, contractual, or defense-in-depth requirements), or for especially sensitive datasets, using a Customer-Managed Encryption Key (CMEK) via Cloud KMS gives the organization independent control: it can rotate the key on its own schedule, audit key usage via Cloud KMS/Cloud Audit Logs, and — critically — instantly render the data unreadable by disabling or destroying the KMS key, providing a "crypto-shredding" capability that Google-managed keys do not offer.

## How Checkov evaluates this
Checkov inspects `encryption_configuration[0].kms_key_name` on the `google_bigquery_table` resource. Any non-empty value (`ANY_VALUE`) causes a PASS — i.e., Checkov doesn't validate the specific key, only that a customer KMS key reference is present. If `encryption_configuration` or `kms_key_name` is absent, the check FAILS.

## Non-compliant example
```hcl
resource "google_bigquery_table" "auth0_logs_external" {
  dataset_id = google_bigquery_dataset.auth0.dataset_id
  table_id   = "auth0_logs_external"

  # encryption_configuration omitted -> Google-managed key only
}
```

## Remediated example
```hcl
resource "google_bigquery_table" "auth0_logs_external" {
  dataset_id = google_bigquery_dataset.auth0.dataset_id
  table_id   = "auth0_logs_external"

  encryption_configuration {
    kms_key_name = google_kms_crypto_key.bq_key.id
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring and key (`google_kms_key_ring` / `google_kms_crypto_key`) in a region compatible with the BigQuery dataset's location.
2. Grant the BigQuery service account (`bq-<project_number>@bigquery-encryption.iam.gserviceaccount.com`) the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on that key.
3. Add an `encryption_configuration { kms_key_name = ... }` block referencing the key on the table (or set it at the dataset level so it applies to new tables by default — see CKV_GCP_81).
4. Note: CMEK can typically only be set at table creation time; applying this to an existing table without CMEK configured may require recreating the table (export/reimport data), so plan for a migration window and validate downstream query/permission impacts.
5. Establish a key rotation policy and monitor Cloud KMS audit logs for key usage.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/BigQueryTableEncryptedWithCMK.py)
- [Google Cloud: Protecting data with Cloud KMS keys (BigQuery CMEK)](https://cloud.google.com/bigquery/docs/customer-managed-encryption)
