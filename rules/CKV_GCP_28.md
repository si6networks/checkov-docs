# CKV_GCP_28: Ensure that Cloud Storage bucket is not anonymously or publicly accessible
## Severity
**CRITICAL** (score: 9.2/10)

An IAM binding granting allUsers or allAuthenticatedUsers access to a Cloud Storage bucket makes bucket contents publicly readable or writable to anyone on the internet with no authentication.

## Summary
This check fails when a `google_storage_bucket_iam_binding` or `google_storage_bucket_iam_member` resource grants a role to the special principals `allUsers` or `allAuthenticatedUsers`.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `google_storage_bucket_iam_binding`, `google_storage_bucket_iam_member`
- **Check type:** resource

## Why it matters
Granting `allUsers` makes bucket contents readable/writable (depending on role) by literally anyone on the internet, unauthenticated; `allAuthenticatedUsers` opens it to anyone with any Google account, which in practice is nearly as broad. GCS buckets frequently store backups, application data, logs, ML datasets, or user uploads containing PII or credentials. Public GCS buckets are among the most common cloud data breach vectors — misconfigurations of exactly this kind have led to real exposures of medical records, financial data, and source code. Unlike a one-off console mistake, an IaC resource with this misconfiguration will be reliably reapplied every time the module runs, making it a persistent rather than transient exposure.

## How Checkov evaluates this
The check collects the effective member(s) from either:
- `member` (singular, for `google_storage_bucket_iam_member`), or
- `members` (list, for `google_storage_bucket_iam_binding`)

- **FAIL** — the combined member list contains `allUsers` or `allAuthenticatedUsers`.
- **PASS** — otherwise (only specific user/group/service-account/domain principals).

## Non-compliant example
```hcl
resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
```

## Remediated example
```hcl
resource "google_storage_bucket_iam_member" "scoped_read" {
  bucket = google_storage_bucket.assets.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:frontend-app@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Remove any `member`/`members` entry equal to `allUsers` or `allAuthenticatedUsers`.
2. Grant access to specific `user:`, `group:`, `serviceAccount:`, or `domain:` principals instead.
3. If you genuinely need to serve public static assets (e.g., a public CDN-backed website bucket), use a dedicated, clearly-named bucket for that purpose only, ideally fronted by Cloud CDN/Cloud Armor rather than granting raw public IAM read access — and ensure no sensitive data ever lands in that bucket.
4. Also check for public access at the bucket-level `IAM policy` / legacy ACLs outside Terraform (console-applied "allUsers" grants won't show up in your Terraform diff) — audit with `gcloud storage buckets get-iam-policy` or the Cloud Console's public-access warnings.
5. Enable **Public Access Prevention** (`public_access_prevention = "enforced"` on the bucket) as an additional guardrail so these bindings can't even be created.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleStorageBucketNotPublic.py
- GCP docs: https://cloud.google.com/storage/docs/access-control/making-data-public
