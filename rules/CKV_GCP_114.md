# CKV_GCP_114: Ensure public access prevention is enforced on Cloud Storage bucket

## Severity
**HIGH** (score: 8.0/10)

Without enforced public access prevention, a single misconfigured ACL or bucket IAM binding can expose bucket contents to the internet, and this control is the backstop that blocks that outcome even if other layers fail.

## Summary
This check requires every `google_storage_bucket` to set `public_access_prevention = "enforced"`, which blocks the bucket (and its objects) from ever being made publicly accessible via ACLs or IAM, regardless of other settings.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_storage_bucket`
- **Check type:** resource (value check)

## Why it matters
Cloud Storage buckets can be made public through several independent mechanisms: bucket-level or object-level ACLs, IAM bindings granting `allUsers`/`allAuthenticatedUsers`, or a combination of misconfigurations that accumulate over time. Public Access Prevention (PAP) is a bucket-level guardrail that overrides all of those paths at once — even if someone later adds a public ACL or an `allUsers` IAM binding, PAP blocks it from taking effect. Without PAP enforced, a single mistaken IAM change (by a person or an automated pipeline) can expose bucket contents to the entire internet. This is one of the most common real-world cloud data breach vectors (leaked source code, PII, backups, logs, and secrets sitting in unintentionally public buckets).

## How Checkov evaluates this
The check (`GoogleStoragePublicAccessPrevention`) is a simple value check:
- It inspects the `public_access_prevention` attribute on `google_storage_bucket`.
- **PASS** only if the value is exactly `"enforced"`.
- Any other value (e.g. `"inherited"`, unset, or a typo) results in **FAIL**.

## Non-compliant example
```hcl
resource "google_storage_bucket" "auth0_logs" {
  name     = "my-project-auth0-logs"
  location = "US"

  uniform_bucket_level_access = true
  # public_access_prevention not set (defaults to "inherited")
}
```

## Remediated example
```hcl
resource "google_storage_bucket" "auth0_logs" {
  name     = "my-project-auth0-logs"
  location = "US"

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"   # <-- added
}
```

## Remediation steps
1. Add `public_access_prevention = "enforced"` to every `google_storage_bucket` resource.
2. Ensure `uniform_bucket_level_access = true` is also set — PAP works most reliably alongside uniform bucket-level access (ACLs disabled), since it removes legacy per-object ACL exposure paths as well.
3. If a bucket must genuinely serve public content (e.g. static website assets, public downloads), treat that as a deliberate, reviewed exception — do not leave PAP unenforced organization-wide to accommodate one bucket.
4. Apply the change; note that toggling `public_access_prevention` does not require bucket recreation, so this is a safe in-place update.
5. Consider setting this as an [organization policy constraint](https://cloud.google.com/storage/docs/org-policy-constraints#public-access-prevention) (`storage.publicAccessPrevention`) so it's enforced even for buckets created outside of this Terraform codebase.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleStoragePublicAccessPrevention.py)
- [GCP Public access prevention documentation](https://cloud.google.com/storage/docs/public-access-prevention)
