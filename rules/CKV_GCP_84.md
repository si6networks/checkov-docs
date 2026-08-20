# CKV_GCP_84: Ensure Artifact Registry Repositories are encrypted with Customer Supplied Encryption Keys (CSEK)
## Severity
**LOW** (score: 2.0/10)

Artifact Registry repositories are encrypted at rest by default, so lacking a CMK reduces customer control over key management for container/artifact content rather than exposing it in plaintext.

## Summary
This check requires every `google_artifact_registry_repository` Terraform resource to set `kms_key_name`, ensuring container images and other build artifacts are encrypted at rest with a customer-managed Cloud KMS key.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_artifact_registry_repository`
- **Check type:** resource (attribute-value check)

## Why it matters
Artifact Registry repositories hold container images, language packages, and other build artifacts that frequently embed secrets, proprietary source, or supply-chain-critical binaries (e.g. the exact image later deployed to production robots/fleet infrastructure, as suggested by the `robodag` module name in this repo). Without a customer-managed key (CMEK), Google's default encryption applies, and the organization has no independent control over key access or the ability to cryptographically revoke access to the repository's contents. If a project or registry is ever decommissioned, compromised, or subject to a legal hold/destruction order, CMEK lets you instantly and verifiably render the artifacts unreadable by disabling/destroying the key, and lets you enforce separate IAM boundaries (who can manage the key vs. who can push/pull images) which is a standard supply-chain security control.

## How Checkov evaluates this
The check (`ArtifactRegistryEncryptedWithCMK`, a `BaseResourceValueCheck`) inspects the `kms_key_name` attribute on `google_artifact_registry_repository`, checking against `ANY_VALUE`.
- **PASS**: `kms_key_name` is set to any non-empty value.
- **FAIL**: `kms_key_name` is absent or empty (default Google-managed encryption).

## Non-compliant example
```hcl
resource "google_artifact_registry_repository" "robodag_image_repo" {
  location      = "us-central1"
  repository_id = "robodag-images"
  format        = "DOCKER"
  # No kms_key_name -> Google-managed encryption only
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "artifacts" {
  name     = "artifact-registry-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "artifacts" {
  name     = "artifact-registry-key"
  key_ring = google_kms_key_ring.artifacts.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_artifact_registry_repository" "robodag_image_repo" {
  location      = "us-central1"
  repository_id = "robodag-images"
  format        = "DOCKER"
  kms_key_name  = google_kms_crypto_key.artifacts.id
}
```

## Remediation steps
1. Create a Cloud KMS key ring/crypto key in the same location as the Artifact Registry repository (CMEK requires location parity).
2. Grant the Artifact Registry service agent (`service-<PROJECT_NUMBER>@gcp-sa-artifactregistry.iam.gserviceaccount.com`) `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key.
3. Set `kms_key_name` when creating the repository — `kms_key_name` is set at repository creation time and cannot be changed afterward; changing it requires recreating the repository (and re-pushing all artifacts).
4. Because this repository backs the `robodag` build pipeline, coordinate the migration with CI/CD to avoid pushing images to a stale, unencrypted repository during cutover.
5. Add `prevent_destroy` on the KMS key (see CKV_GCP_82) so the repository doesn't lose access to its artifacts if the key is accidentally destroyed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/ArtifactRegsitryEncryptedWithCMK.py
- GCP docs: https://cloud.google.com/artifact-registry/docs/cmek
