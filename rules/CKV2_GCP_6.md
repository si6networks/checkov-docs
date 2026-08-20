# CKV2_GCP_6: Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible

## Severity
**CRITICAL** (score: 9.1/10)

A KMS crypto key IAM binding granting allUsers/allAuthenticatedUsers means anyone on the internet can use the key to encrypt or decrypt data, directly compromising the confidentiality of everything it protects.

## Summary
This check ensures that no IAM binding or IAM member on a `google_kms_crypto_key` grants access to `allUsers` or `allAuthenticatedUsers`, which would make the encryption key usable by anyone on the internet or anyone with a Google account.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `google_kms_crypto_key`, `google_kms_crypto_key_iam_binding`, `google_kms_crypto_key_iam_member`

This is a graph-based check (Checkov "graph check", defined as JSON) that inspects IAM binding/member resources connected to the crypto key.

## Why it matters
A Cloud KMS crypto key is used to encrypt and decrypt sensitive data — database contents, secrets, disk volumes, application-level payloads. If the key's IAM policy grants permissions (such as `roles/cloudkms.cryptoKeyEncrypterDecrypter` or `roles/cloudkms.cryptoKeyDecrypter`) to the special members `allUsers` (literally anyone on the internet, unauthenticated) or `allAuthenticatedUsers` (any Google account holder, not just people in your organization), any external party could potentially decrypt data protected by that key or encrypt malicious data in a way trusted by your systems. This completely undermines the confidentiality guarantee that encryption is supposed to provide — the key material itself might stay secret, but its use is thrown open to the world.

## How Checkov evaluates this
The check filters for `google_kms_crypto_key` resources, then examines any connected IAM member/binding resources:
- For `google_kms_crypto_key_iam_member`: passes if no such resource is connected, OR if connected, its `member` attribute is not equal to `allAuthenticatedUsers` and not equal to `allUsers`.
- For `google_kms_crypto_key_iam_binding`: passes if no such resource is connected, OR if connected, its `members` list does not contain `allAuthenticatedUsers` and does not contain `allUsers`.

Both conditions must hold (AND) for the overall check to pass. The check **fails** if any IAM member/binding attached to the crypto key grants access to `allUsers` or `allAuthenticatedUsers`.

## Non-compliant example
```hcl
resource "google_kms_crypto_key" "key" {
  name     = "app-secret-key"
  key_ring = google_kms_key_ring.keyring.id
}

resource "google_kms_crypto_key_iam_member" "public" {
  crypto_key_id = google_kms_crypto_key.key.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "allUsers"
}
```

## Remediated example
```hcl
resource "google_kms_crypto_key" "key" {
  name     = "app-secret-key"
  key_ring = google_kms_key_ring.keyring.id
}

resource "google_kms_crypto_key_iam_member" "app_sa" {
  crypto_key_id = google_kms_crypto_key.key.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:app-sa@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Remove any `google_kms_crypto_key_iam_member` or `google_kms_crypto_key_iam_binding` resource that lists `member`/`members` as `allUsers` or `allAuthenticatedUsers`.
2. Replace public members with specific `serviceAccount:`, `user:`, or `group:` principals scoped to least privilege.
3. Audit the current live IAM policy with `gcloud kms keys get-iam-policy` to confirm no public bindings exist outside of Terraform state (e.g., applied manually via console).
4. Use `roles/cloudkms.cryptoKeyEncrypterDecrypter`, `cryptoKeyEncrypter`, or `cryptoKeyDecrypter` scoped to the minimum operation each principal actually needs, rather than a broad role.
5. Enable Cloud Audit Logs for Cloud KMS to detect any future attempt to grant public access.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPKMSCryptoKeysAreNotPubliclyAccessible.json
- Google Cloud docs: https://cloud.google.com/kms/docs/reference/permissions-and-roles
