# CKV_GCP_81: Ensure Big Query Datasets are encrypted with Customer Supplied/Managed Encryption Keys (CMEK)
## Severity
**LOW** (score: 2.0/10)

The dataset-level default-CMEK counterpart to CKV_GCP_80; missing it risks new tables silently inheriting Google-managed-only encryption rather than removing encryption at rest altogether.

## Summary
This check ensures a `google_bigquery_dataset` sets a default customer-managed KMS key, so any table created in that dataset inherits CMEK encryption rather than relying solely on Google's default encryption-at-rest.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_bigquery_dataset`

## Why it matters
This is the dataset-level counterpart to CKV_GCP_80. Setting a default CMEK key on the dataset means every new table created within it automatically inherits customer-managed encryption without each table author needing to remember to configure it individually — closing the gap where an otherwise CMEK-compliant environment gets undermined by one forgotten table. Without a dataset default key, engineers creating ad-hoc or pipeline-generated tables (which is extremely common in BigQuery workflows) will silently fall back to Google-managed keys, breaking the organization's key-control, audit, and crypto-shredding capabilities for that data without anyone necessarily noticing at review time.

## How Checkov evaluates this
Checkov inspects `default_encryption_configuration[0].kms_key_name` on the `google_bigquery_dataset` resource. Any non-empty value (`ANY_VALUE`) causes a PASS. If `default_encryption_configuration` or `kms_key_name` is absent, the check FAILS.

## Non-compliant example
```hcl
resource "google_bigquery_dataset" "auth0" {
  dataset_id = "auth0_logs"
  location   = "US"

  # default_encryption_configuration omitted -> tables default to Google-managed keys
}
```

## Remediated example
```hcl
resource "google_bigquery_dataset" "auth0" {
  dataset_id = "auth0_logs"
  location   = "US"

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bq_key.id
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring and key in a region compatible with the dataset's location (multi-region datasets need a key location that matches, e.g. a multi-region KMS key ring).
2. Grant the BigQuery service agent (`bq-<project_number>@bigquery-encryption.iam.gserviceaccount.com`) the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on the key.
3. Add a `default_encryption_configuration { kms_key_name = ... }` block to the `google_bigquery_dataset` resource.
4. Note: this sets the *default* for new tables going forward — existing tables in the dataset that were created without CMEK are not retroactively re-encrypted; each existing table still needs to be individually migrated (see CKV_GCP_80) if it must also be CMEK-protected.
5. Verify the KMS key's region/multi-region matches the dataset location — a mismatch will cause table/dataset creation to fail.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/BigQueryDatasetEncryptedWithCMK.py)
- [Google Cloud: Protecting data with Cloud KMS keys (BigQuery CMEK)](https://cloud.google.com/bigquery/docs/customer-managed-encryption)
