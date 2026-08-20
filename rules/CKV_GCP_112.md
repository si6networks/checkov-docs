# CKV_GCP_112: Ensure KMS policy should not allow public access

## Severity
**HIGH** (score: 7.5/10)

A public IAM binding (allUsers/allAuthenticatedUsers) on a KMS crypto key lets anyone encrypt or decrypt data protected by that key, effectively neutralizing the encryption control for every resource that relies on it.

## Summary
This check fails when a Google Cloud KMS (Key Management Service) crypto key IAM policy grants access to `allUsers` or `allAuthenticatedUsers`, which would let anyone on the internet (or anyone with a Google account) use the key.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_kms_crypto_key_iam_policy`, `google_kms_crypto_key_iam_binding`, `google_kms_crypto_key_iam_member`
- **Check type:** resource

## Why it matters
A KMS crypto key controls who can encrypt, decrypt, or sign data protected by that key. If the IAM policy for the key includes the special members `allUsers` (anyone on the internet, unauthenticated) or `allAuthenticatedUsers` (any Google account holder, not just users in your organization), then any external party could potentially:
- Decrypt data protected by the key (data exposure), if the granted role includes decrypt permissions.
- Encrypt/sign new data using organizational key material, undermining trust in signed artifacts.
- Exhaust key usage quotas or trigger unexpected billing.

Because KMS keys are usually the root of trust protecting sensitive data (database encryption, secret material, disk encryption, etc.), a publicly-bindable KMS IAM policy is one of the most severe misconfigurations possible — it can silently defeat all downstream encryption controls.

## How Checkov evaluates this
The check (`GoogleKMSKeyIsPublic`) inspects the resource configuration for members granted access, depending on which resource type is used:

- For `google_kms_crypto_key_iam_policy` (which supplies a `policy_data` attribute, typically from a `data.google_iam_policy` data source): it walks `policy_data[].bindings[].members[]` and fails if any member string equals `"allUsers"` or `"allAuthenticatedUsers"`.
- For `google_kms_crypto_key_iam_binding` (which supplies a `members` list attribute): it checks the first `members` list entry set and fails if any entry is `"allUsers"` or `"allAuthenticatedUsers"`.
- For `google_kms_crypto_key_iam_member` (which supplies a single `member` attribute): it fails if that single member is `"allUsers"` or `"allAuthenticatedUsers"`.

If none of `policy_data`, `members`, or `member` is present, the result is `UNKNOWN` (cannot be evaluated).

## Non-compliant example
```hcl
resource "google_kms_crypto_key_iam_member" "public_key_access" {
  crypto_key_id = google_kms_crypto_key.example.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "allUsers"
}
```

## Remediated example
```hcl
resource "google_kms_crypto_key_iam_member" "restricted_key_access" {
  crypto_key_id = google_kms_crypto_key.example.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:app-sa@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Search Terraform code for `google_kms_crypto_key_iam_member`, `google_kms_crypto_key_iam_binding`, and `google_kms_crypto_key_iam_policy` resources.
2. Replace any `member`/`members` value of `allUsers` or `allAuthenticatedUsers` with specific principals: `user:`, `serviceAccount:`, `group:`, or `domain:` identifiers.
3. If broad access was intended for a legitimate reason (e.g., a public verification key), use a dedicated, non-sensitive key and document the exception rather than granting `allUsers` on production key material.
4. Re-run `terraform plan` and verify the IAM diff only grants the intended principals.
5. Audit existing deployed KMS key policies with `gcloud kms keys get-iam-policy` to catch drift not captured in Terraform state.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleKMSKeyIsPublic.py)
- [Google Cloud KMS IAM permissions and roles](https://cloud.google.com/kms/docs/reference/permissions-and-roles)
