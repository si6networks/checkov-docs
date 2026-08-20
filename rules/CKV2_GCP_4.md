# CKV2_GCP_4: Ensure that retention policies on log buckets are configured using Bucket Lock

## Severity
**LOW** (score: 2.0/10)

Without Bucket Lock enforcing retention on log sink buckets, audit/log data can be deleted or altered before its retention period, undermining forensic integrity even though it does not itself expose data.

## Summary
This check ensures that when a GCP logging sink (organization, folder, or project) writes to a Cloud Storage bucket, that destination bucket has its retention policy locked (`retention_policy.is_locked = true`), so log data cannot be deleted or have its retention period shortened by anyone — including project admins — before the retention period expires.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_logging_folder_sink`, `google_logging_organization_sink`, `google_logging_project_sink`, `google_storage_bucket`

This is a graph-based check (Checkov "graph check", defined as JSON) that inspects connections between logging sinks and their destination storage buckets, rather than a single-resource Python check.

## Why it matters
Audit and application logs are often the primary forensic evidence used to investigate a security incident, detect insider threats, or satisfy regulatory/compliance retention requirements (e.g., SOX, PCI-DSS, HIPAA). If the storage bucket receiving these logs has a retention policy that is *not* locked, any user with sufficient IAM permissions (including a compromised admin account or a malicious insider) can shorten the retention period or delete the policy entirely, and then delete the logs — destroying the evidence trail. Locking the bucket's retention policy makes it immutable: it can never be removed or reduced, even by the bucket owner or a project owner, guaranteeing that log data survives for its full compliance window regardless of who gains access to the bucket's IAM policy later.

## How Checkov evaluates this
The graph check filters for `google_logging_organization_sink`, `google_logging_folder_sink`, and `google_logging_project_sink` resources, then checks their connections to `google_storage_bucket`:
- If the sink has **no connection** to any `google_storage_bucket` (e.g., it writes to BigQuery or Pub/Sub instead), the check **passes** — this specific check does not apply.
- If the sink **is** connected to a `google_storage_bucket`, the check requires that the connected bucket's attribute `retention_policy.is_locked` equals `true`.
- The check **fails** when a sink writes to a storage bucket whose retention policy is missing, unlocked, or set to `is_locked = false`.

## Non-compliant example
```hcl
resource "google_storage_bucket" "log_bucket" {
  name     = "org-audit-logs"
  location = "US"

  retention_policy {
    retention_period = 2592000 # 30 days
    is_locked         = false   # not locked - can be changed/removed later
  }
}

resource "google_logging_project_sink" "audit_sink" {
  name        = "audit-log-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.log_bucket.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""
}
```

## Remediated example
```hcl
resource "google_storage_bucket" "log_bucket" {
  name     = "org-audit-logs"
  location = "US"

  retention_policy {
    retention_period = 2592000 # 30 days
    is_locked         = true    # locked - immutable retention
  }
}

resource "google_logging_project_sink" "audit_sink" {
  name        = "audit-log-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.log_bucket.name}"
  filter      = "logName:\"cloudaudit.googleapis.com\""
}
```

## Remediation steps
1. Add a `retention_policy` block to the destination `google_storage_bucket`, setting an appropriate `retention_period` (in seconds) for your compliance needs.
2. Set `is_locked = true` on that retention policy.
3. **Caution:** locking a bucket's retention policy is irreversible — you cannot shorten the retention period or unlock/delete the policy afterward, and the bucket cannot be deleted until all its objects pass their retention period. Validate the retention period carefully before applying in production.
4. Verify IAM permissions on the bucket separately restrict who can write/delete objects — bucket lock protects the *policy*, not object-level access control.
5. Confirm the logging sink's writer identity has `roles/storage.objectCreator` (least privilege) on the bucket rather than broader storage roles.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/GCPLogBucketsConfiguredUsingLock.json
- Google Cloud docs: https://cloud.google.com/storage/docs/bucket-lock
