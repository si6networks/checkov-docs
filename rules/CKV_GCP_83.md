# CKV_GCP_83: Ensure PubSub Topics are encrypted with Customer Supplied Encryption Keys (CSEK)
## Severity
**LOW** (score: 2.0/10)

PubSub topics are encrypted by Google by default, so a missing CMK removes customer key control and audit/rotation ability over sensitive message data rather than leaving data unencrypted.

## Summary
This check requires every `google_pubsub_topic` Terraform resource to set `kms_key_name`, so that message data at rest is encrypted with a customer-managed Cloud KMS key instead of only Google's default encryption.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_pubsub_topic`
- **Check type:** resource (attribute-value check)

## Why it matters
By default, Pub/Sub encrypts message data at rest with Google-managed encryption keys, which is adequate for baseline protection but gives the customer no control over key lifecycle, rotation cadence, or the ability to revoke access to data by disabling/destroying a key. Using a Customer-Managed Encryption Key (CMEK) via `kms_key_name` means the organization controls the key's IAM policy, rotation schedule, and audit trail through Cloud KMS, and can immediately render all topic data unreadable by disabling the key (a critical capability for incident response, tenant offboarding, or regulatory data-destruction requirements such as GDPR "right to erasure" workflows). Topics carrying sensitive payloads (PII, financial events, health data) without CMEK put the organization out of compliance with data-residency/key-custody requirements common in regulated industries and reduce the blast-radius controls available if the Pub/Sub project or IAM policy is ever compromised.

## How Checkov evaluates this
The check (`CloudPubSubEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the `kms_key_name` attribute of the `google_pubsub_topic` resource, checking against `ANY_VALUE`.
- **PASS**: `kms_key_name` is set to any non-empty value (a KMS key resource ID/self-link).
- **FAIL**: `kms_key_name` is absent or empty.

## Non-compliant example
```hcl
resource "google_pubsub_topic" "events" {
  name = "app-events-topic"
  # No kms_key_name -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "pubsub" {
  name     = "pubsub-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "pubsub" {
  name     = "pubsub-topic-key"
  key_ring = google_kms_key_ring.pubsub.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_pubsub_topic" "events" {
  name         = "app-events-topic"
  kms_key_name = google_kms_crypto_key.pubsub.id
}
```

## Remediation steps
1. Create (or reuse) a Cloud KMS key ring and crypto key in a location compatible with the topic (Pub/Sub CMEK requires the key and topic to be in compatible regions, or the key ring in a multi-region/global location).
2. Grant the Pub/Sub service agent (`service-<PROJECT_NUMBER>@gcp-sa-pubsub.iam.gserviceaccount.com`) the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role on the key.
3. Set `kms_key_name` on the `google_pubsub_topic` resource to the crypto key's resource ID.
4. Note: `kms_key_name` cannot be added to an existing topic after creation via update in all provider versions — verify whether your provider version supports in-place update or requires resource replacement, and plan for a migration (new topic + subscriber cutover) if needed.
5. Combine with `CKV_GCP_82`-style `prevent_destroy` on the backing KMS key to avoid an accidental key deletion breaking the topic.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudPubSubEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/pubsub/docs/encryption
