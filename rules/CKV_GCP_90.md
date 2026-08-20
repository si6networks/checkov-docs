# CKV_GCP_90: Ensure data flow jobs are encrypted with Customer Supplied Encryption Keys (CSEK)
## Severity
**LOW** (score: 2.0/10)

Dataflow jobs are encrypted by default, so lacking a CMK reduces customer control over encryption keys for data processed in the pipeline rather than leaving it unencrypted.

## Summary
This check requires `google_dataflow_job` Terraform resources to set `kms_key_name`, so that data processed and staged by the Dataflow job is encrypted at rest with a customer-managed Cloud KMS key.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_dataflow_job`
- **Check type:** resource (attribute-value check)

## Why it matters
Dataflow jobs read from and write to potentially sensitive data sources (as indicated by this repo's `dataflow-pubsub-bigquery` pipeline, which moves data from Pub/Sub into BigQuery) and stage intermediate state/shuffle data in Cloud Storage and temporary Compute Engine disks during execution. Without CMEK, all of this staged and at-rest data relies solely on Google-managed keys, denying the organization independent control over key rotation and the ability to cryptographically revoke access. For a pipeline moving data between messaging and analytics/warehousing tiers, CMEK ensures consistent key custody across the whole data path, supports compliance requirements that mandate customer-controlled encryption keys, and provides an emergency "kill switch" to cut off access to data at rest if the pipeline's project or credentials are ever compromised.

## How Checkov evaluates this
The check (`DataflowJobEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the `kms_key_name` attribute on `google_dataflow_job`, checking against `ANY_VALUE`.
- **PASS**: `kms_key_name` is set to any non-empty value.
- **FAIL**: `kms_key_name` is absent or empty.

## Non-compliant example
```hcl
resource "google_dataflow_job" "pubsub_to_bq" {
  name              = "pubsub-to-bigquery"
  template_gcs_path = "gs://dataflow-templates/latest/PubSub_to_BigQuery"
  temp_gcs_location  = "gs://my-bucket/temp"

  parameters = {
    inputTopic     = "projects/my-project/topics/events"
    outputTableSpec = "my-project:dataset.events"
  }
  # No kms_key_name -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "dataflow" {
  name     = "dataflow-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "dataflow" {
  name     = "dataflow-key"
  key_ring = google_kms_key_ring.dataflow.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_dataflow_job" "pubsub_to_bq" {
  name              = "pubsub-to-bigquery"
  template_gcs_path = "gs://dataflow-templates/latest/PubSub_to_BigQuery"
  temp_gcs_location  = "gs://my-bucket/temp"
  kms_key_name       = google_kms_crypto_key.dataflow.id

  parameters = {
    inputTopic      = "projects/my-project/topics/events"
    outputTableSpec = "my-project:dataset.events"
  }
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same region as the Dataflow job's `temp_gcs_location`/worker region.
2. Grant the Dataflow service agent (`service-<PROJECT_NUMBER>@dataflow-service-producer-prod.iam.gserviceaccount.com`) and the Compute Engine default service account (or the custom worker SA) `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Set `kms_key_name` on the `google_dataflow_job` resource — this affects the job's worker disks and shuffle data encryption.
4. Because `google_dataflow_job` resources are typically immutable/replace-on-change in Terraform, expect this to trigger a job replacement (stop and relaunch) rather than an in-place update — plan for a brief pipeline interruption or use Dataflow's Update/drain feature outside Terraform if zero-downtime migration is required.
5. Verify the downstream BigQuery dataset/table and the source Pub/Sub topic also use CMEK if end-to-end customer-key custody is required (this check only covers the Dataflow job itself).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataflowJobEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/dataflow/docs/guides/customer-managed-encryption-keys
