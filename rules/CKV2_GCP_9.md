# CKV2_GCP_9: Ensure that Container Registry repositories are not anonymously or publicly accessible

## Severity
**CRITICAL** (score: 9.0/10)

Publicly/anonymously accessible Container Registry storage buckets let anyone pull (and potentially push/tamper) private container images, risking IP leakage and supply-chain compromise of downstream deployments.

## Summary
This check ensures that the underlying Cloud Storage bucket backing a `google_container_registry` (legacy GCR) has no IAM binding or member granting access to `allUsers` or `allAuthenticatedUsers`, which would expose all pushed container images to the public.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_container_registry`, `google_storage_bucket_iam_binding`, `google_storage_bucket_iam_member`

This is a graph-based check (Checkov "graph check", defined as JSON). Legacy Google Container Registry stores images in a Cloud Storage bucket (`artifacts.<project>.appspot.com` or similar), so this check examines the storage-bucket-level IAM grants connected to the registry.

## Why it matters
Container images frequently embed application source code, dependency manifests, configuration files, and sometimes accidentally-baked-in secrets (API keys, credentials, private keys). If the storage bucket behind Container Registry grants read access to `allUsers` (unauthenticated internet) or `allAuthenticatedUsers` (any Google account holder), anyone could pull and inspect your images — potentially exfiltrating proprietary code or embedded secrets, or fingerprinting your infrastructure to plan further attacks. A publicly writable grant would be even worse, allowing an attacker to push malicious images that could be pulled and run by your own deployment pipelines (a supply-chain attack vector).

## How Checkov evaluates this
The check filters for `google_container_registry` resources, then examines any connected `google_storage_bucket_iam_member`/`google_storage_bucket_iam_binding` resources:
- For `google_storage_bucket_iam_member`: passes if none is connected, OR if connected, its `member` is not `allAuthenticatedUsers` and not `allUsers`.
- For `google_storage_bucket_iam_binding`: passes if none is connected, OR if connected, its `members` list does not contain `allAuthenticatedUsers` and does not contain `allUsers`.

The check **fails** if any connected storage IAM member/binding grants access to `allUsers` or `allAuthenticatedUsers`.

## Non-compliant example
```hcl
resource "google_container_registry" "registry" {
  project = "my-project"
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_container_registry.registry.bucket_self_link
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
```

## Remediated example
```hcl
resource "google_container_registry" "registry" {
  project = "my-project"
}

resource "google_storage_bucket_iam_member" "ci_pull" {
  bucket = google_container_registry.registry.bucket_self_link
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:ci-runner@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Remove any `google_storage_bucket_iam_member`/`google_storage_bucket_iam_binding` on the GCR-backing bucket that lists `allUsers` or `allAuthenticatedUsers`.
2. Grant `roles/storage.objectViewer` (pull) or `roles/storage.admin` (push/pull) only to specific service accounts, users, or groups that need registry access.
3. Consider migrating from legacy Container Registry to Artifact Registry, which offers more granular, repository-level IAM controls (`google_artifact_registry_repository_iam_*`) instead of bucket-level grants.
4. Audit the live bucket IAM policy with `gsutil iam get gs://artifacts.<project>.appspot.com` to confirm no public grants exist outside Terraform state.
5. Scan existing images for embedded secrets before/after locking down access, since prior public exposure may already have leaked data.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPContainerRegistryReposAreNotPubliclyAccessible.json
- Google Cloud docs: https://cloud.google.com/container-registry/docs/access-control
