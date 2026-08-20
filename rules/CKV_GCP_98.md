# CKV_GCP_98: Ensure that Dataproc clusters are not anonymously or publicly accessible
## Severity
**CRITICAL** (score: 8.5/10)

This detects Dataproc cluster IAM bindings/members granting access to allUsers or allAuthenticatedUsers, meaning the cluster can be reached and managed without any authentication or identity check at all.

## Summary
This check flags `google_dataproc_cluster_iam_member` and `google_dataproc_cluster_iam_binding` resources that grant IAM access to a Dataproc cluster to the special public principals `allUsers` or `allAuthenticatedUsers`.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_dataproc_cluster_iam_member`, `google_dataproc_cluster_iam_binding`
- **Check type:** resource (custom `scan_resource_conf` logic, not a simple attribute-value check)

## Why it matters
Granting `allUsers` or `allAuthenticatedUsers` on a Dataproc cluster's IAM policy means, respectively, literally anyone on the internet, or any authenticated Google account holder anywhere (not just members of your organization), can be granted whatever role is bound (e.g., `roles/dataproc.editor`, `roles/dataproc.worker`, or even a viewer role that exposes cluster configuration and job details). Dataproc clusters process business data and often have service accounts with broad access to Cloud Storage, BigQuery, or other project resources; a public grant on the cluster's IAM policy is one of the most direct ways a GCP resource can be exposed to anonymous internet-wide access, comparable in severity to a public storage bucket, and is a classic vector for accidental cloud data exposure incidents that arise from copy-pasted example configs or reused Terraform modules.

## How Checkov evaluates this
The check (`DataprocPrivateCluster`, a custom `BaseResourceCheck`) examines the IAM member/binding configuration for the two supported resource types:
- For `google_dataproc_cluster_iam_member`: reads the single `member` value and fails if it equals `"allUsers"` or `"allAuthenticatedUsers"`.
- For `google_dataproc_cluster_iam_binding`: reads the `members` list and fails if **any** entry equals `"allUsers"` or `"allAuthenticatedUsers"`.
- **PASS**: no public principal is present in the member(s).
- **FAIL**: `allUsers` or `allAuthenticatedUsers` appears as the member (or one of the members).

## Non-compliant example
```hcl
resource "google_dataproc_cluster_iam_member" "public_viewer" {
  cluster = google_dataproc_cluster.analytics.name
  role    = "roles/dataproc.viewer"
  member  = "allUsers"
}
```
```hcl
resource "google_dataproc_cluster_iam_binding" "public_binding" {
  cluster = google_dataproc_cluster.analytics.name
  role    = "roles/dataproc.editor"
  members = [
    "allAuthenticatedUsers",
    "group:data-team@example.com",
  ]
}
```

## Remediated example
```hcl
resource "google_dataproc_cluster_iam_member" "scoped_viewer" {
  cluster = google_dataproc_cluster.analytics.name
  role    = "roles/dataproc.viewer"
  member  = "group:data-team@example.com"
}
```
```hcl
resource "google_dataproc_cluster_iam_binding" "scoped_binding" {
  cluster = google_dataproc_cluster.analytics.name
  role    = "roles/dataproc.editor"
  members = [
    "group:data-team@example.com",
    "serviceAccount:etl-runner@my-project.iam.gserviceaccount.com",
  ]
}
```

## Remediation steps
1. Remove any `member`/`members` entry equal to `allUsers` or `allAuthenticatedUsers` from the resource.
2. Replace it with specific principals: `user:`, `group:`, `serviceAccount:`, or `domain:` (the last still restricts to a specific Workspace domain, not the public).
3. If broad discoverability was actually intended (rare for Dataproc), reconsider the design — cluster-level access should almost always be scoped to specific engineering/data teams or automation service accounts.
4. Audit existing deployed clusters directly in GCP (`gcloud dataproc clusters get-iam-policy`) in case a public binding was applied outside Terraform and is not represented in this configuration at all.
5. After remediation, confirm the affected teams/service accounts still have the access they legitimately need via the narrowed grant, to avoid breaking existing pipelines.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataprocPrivateCluster.py
- GCP docs: https://cloud.google.com/iam/docs/overview#allusers_and_allauthenticatedusers
