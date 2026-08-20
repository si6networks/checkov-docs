# CKV_GCP_113: Ensure IAM policy should not define public access

## Severity
**HIGH** (score: 7.5/10)

A google_iam_policy binding that grants allUsers/allAuthenticatedUsers hands the bound role's permissions to anyone on the internet, which for anything beyond a trivially low-privilege role is a direct path to data exposure or resource takeover.

## Summary
This check fails when a `google_iam_policy` Terraform data source defines a binding whose `members` list includes `allUsers` or `allAuthenticatedUsers`, i.e. the policy document itself grants public access before it's even attached to a resource.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Entity type:** `google_iam_policy` (a `data` source, not a resource)
- **Check type:** data

## Why it matters
The `google_iam_policy` data source is commonly used to author a reusable IAM policy document that is then applied to many different GCP resources (buckets, KMS keys, Pub/Sub topics, service accounts, etc.) via `*_iam_policy` resources. Because a single policy document can be reused across multiple resources, a public grant baked into it propagates to every resource it's attached to. Catching the problem at the data-source level — before it fans out — prevents a single mistake from silently making many resources public simultaneously (e.g. every bucket or key that references the shared policy document).

## How Checkov evaluates this
The check (`GooglePolicyIsPrivate`) inspects the data source's `binding` blocks:
- It iterates each `binding` block.
- For each binding, it looks at the `members` attribute (a list).
- If any member in that list equals `"allUsers"` or `"allAuthenticatedUsers"`, the check returns `FAILED` (evaluated key recorded as `bindings/[0]/members`).
- If bindings exist and no disallowed member is found, it returns `PASSED`.
- If there is no `binding` block at all (or it isn't a list), the result is `UNKNOWN`.

## Non-compliant example
```hcl
data "google_iam_policy" "public_policy" {
  binding {
    role = "roles/storage.objectViewer"
    members = [
      "allUsers",
    ]
  }
}

resource "google_storage_bucket_iam_policy" "policy" {
  bucket      = google_storage_bucket.example.name
  policy_data = data.google_iam_policy.public_policy.policy_data
}
```

## Remediated example
```hcl
data "google_iam_policy" "restricted_policy" {
  binding {
    role = "roles/storage.objectViewer"
    members = [
      "group:analytics-readers@my-org.com",
    ]
  }
}

resource "google_storage_bucket_iam_policy" "policy" {
  bucket      = google_storage_bucket.example.name
  policy_data = data.google_iam_policy.restricted_policy.policy_data
}
```

## Remediation steps
1. Locate all `data "google_iam_policy"` blocks in your Terraform configuration.
2. Replace any `allUsers` or `allAuthenticatedUsers` entries in `binding.members` with specific `user:`, `serviceAccount:`, `group:`, or `domain:` principals.
3. Check every resource that consumes `policy_data` from this data source (e.g. `google_storage_bucket_iam_policy`, `google_kms_crypto_key_iam_policy`, `google_project_iam_policy`) — since the fix applies to the shared document, all downstream attachments are corrected at once.
4. If a public grant is genuinely required (e.g. a public static-assets bucket), scope it to a dedicated resource rather than a shared/reused policy document, and document the exception.
5. Re-run `terraform plan` to confirm which resources' effective IAM bindings changed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/gcp/GooglePolicyIsPrivate.py)
- [Terraform `google_iam_policy` data source](https://registry.terraform.io/providers/hashicorp/google/latest/docs/data-sources/iam_policy)
