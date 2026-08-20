# CKV2_GCP_3: Ensure that there are only GCP-managed service account keys for each service account
## Severity
**LOW** (score: 2.0/10)

User-managed GCP service account keys are long-lived, exportable credential material that Google does not automatically rotate, so their presence significantly increases the risk of credential leakage and unauthorized account use compared to GCP-managed keys.

## Summary
This check ensures that service account keys are GCP-managed (system-generated) rather than user-managed keys with externally supplied public key material.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_service_account_key`

## Why it matters
User-managed service account keys (where a `public_key_data` value is supplied) are long-lived credentials whose private key material exists outside GCP's control — typically generated locally and downloaded as a JSON/P12 file. These keys have no automatic rotation, are easy to leak (accidentally committed to source control, left in CI logs, copied to laptops), and if compromised grant persistent access to whatever IAM roles the service account holds, often with no built-in expiration. GCP-managed keys, by contrast, are used internally by Google services (e.g., default Compute Engine service account credentials) and are not exportable as private key files, dramatically reducing the risk of key exfiltration. Google explicitly recommends avoiding downloadable user-managed service account keys altogether in favor of keyless authentication mechanisms (Workload Identity, Workload Identity Federation, attached service accounts).

## How Checkov evaluates this
This is a Terraform graph-based check (single attribute check) on `google_service_account_key`:
- **PASS** if `public_key_data` does **not** exist on the resource (i.e., it's a GCP-managed key, or the key is being created without externally supplied public key material).
- **FAIL** if `public_key_data` is set (indicating a user-managed key uploaded with externally generated key material).

## Non-compliant example
```hcl
resource "google_service_account" "sa" {
  account_id   = "my-app-sa"
  display_name = "My App Service Account"
}

resource "google_service_account_key" "key" {
  service_account_id = google_service_account.sa.name
  public_key_data     = filebase64("external-public-key.pem")  # user-managed key material
}
```

## Remediated example
```hcl
resource "google_service_account" "sa" {
  account_id   = "my-app-sa"
  display_name = "My App Service Account"
}

resource "google_service_account_key" "key" {
  service_account_id = google_service_account.sa.name
  # no public_key_data -> GCP generates and manages the key pair
}
```

## Remediation steps
1. Remove any `public_key_data` attribute from `google_service_account_key` resources so GCP generates the key pair itself, or better:
2. Eliminate downloadable service account keys entirely where possible — use Workload Identity Federation (for external/CI workloads) or attached service accounts (for GCE/GKE/Cloud Run workloads) instead of `google_service_account_key` resources.
3. For any keys that must remain, enforce short lifetimes and rotation via organization policy (`iam.serviceAccountKeyExpiryHours` constraint) and monitor key age with Security Command Center or a custom detector.
4. Audit existing keys with `gcloud iam service-accounts keys list --iam-account=<SA_EMAIL>` and revoke/delete unused or externally-generated keys.
5. Removing/rotating a key that is actively used by an application will break that application's authentication until it's updated with new credentials — coordinate the rotation.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/ServiceAccountHasGCPmanagedKey.json
- GCP docs: https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys
