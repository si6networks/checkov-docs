# CKV2_GCP_8: Ensure that Cloud KMS Key Rings are not anonymously or publicly accessible

## Severity
**CRITICAL** (score: 9.1/10)

Public IAM bindings (allUsers/allAuthenticatedUsers) on a KMS key ring let unauthenticated or any-authenticated principals manage/use every key it contains, exposing all data encrypted under those keys.

## Summary
This check ensures that no IAM binding or IAM member on a `google_kms_key_ring` grants access to `allUsers` or `allAuthenticatedUsers`, which would make every crypto key in that key ring usable by anyone on the internet or anyone with a Google account.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_kms_key_ring`, `google_kms_key_ring_iam_binding`, `google_kms_key_ring_iam_member`

This is a graph-based check (Checkov "graph check", defined as JSON) that inspects IAM binding/member resources connected to the key ring.

## Why it matters
A Cloud KMS key ring is a container for one or more crypto keys, and IAM permissions granted at the key-ring level are inherited by every key within it. If the key ring's IAM policy grants a role to `allUsers` (anyone on the internet, unauthenticated) or `allAuthenticatedUsers` (any Google account holder, not limited to your org), then *every current and future key* in that ring inherits that public exposure. This is more severe than exposing a single key, because it silently compromises new keys added later without anyone realizing the container itself is public. It defeats the entire purpose of encryption: data protected by any key in the ring could be decrypted, or encrypted on behalf of your systems, by an untrusted party.

## How Checkov evaluates this
The check filters for `google_kms_key_ring` resources, then examines any connected IAM member/binding resources:
- For `google_kms_key_ring_iam_member`: passes if no such resource is connected, OR if connected, its `member` attribute is not `allAuthenticatedUsers` and not `allUsers`.
- For `google_kms_key_ring_iam_binding`: passes if no such resource is connected, OR if connected, its `members` list does not contain `allAuthenticatedUsers` and does not contain `allUsers`.

Both conditions must hold for the overall check to pass. The check **fails** if any IAM member/binding attached to the key ring grants access to `allUsers` or `allAuthenticatedUsers`.

## Non-compliant example
```hcl
resource "google_kms_key_ring" "keyring" {
  name     = "app-keyring"
  location = "us-central1"
}

resource "google_kms_key_ring_iam_binding" "public" {
  key_ring_id = google_kms_key_ring.keyring.id
  role        = "roles/cloudkms.cryptoKeyDecrypter"
  members     = ["allAuthenticatedUsers"]
}
```

## Remediated example
```hcl
resource "google_kms_key_ring" "keyring" {
  name     = "app-keyring"
  location = "us-central1"
}

resource "google_kms_key_ring_iam_binding" "app_team" {
  key_ring_id = google_kms_key_ring.keyring.id
  role        = "roles/cloudkms.cryptoKeyDecrypter"
  members     = ["group:app-team@example.com"]
}
```

## Remediation steps
1. Remove any `google_kms_key_ring_iam_member` or `google_kms_key_ring_iam_binding` that lists `allUsers` or `allAuthenticatedUsers`.
2. Grant permissions instead to specific `serviceAccount:`, `user:`, or `group:` principals following least privilege.
3. If different keys within the ring need different access levels, move the IAM grants down to the individual `google_kms_crypto_key_iam_*` resources instead of the key ring level, so access is scoped precisely.
4. Audit live IAM policy with `gcloud kms keyrings get-iam-policy` to catch grants made outside Terraform.
5. Enable Cloud Audit Logs for Cloud KMS to alert on any future public-grant attempts.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPKMSKeyRingsAreNotPubliclyAccessible.json
- Google Cloud docs: https://cloud.google.com/kms/docs/reference/permissions-and-roles
