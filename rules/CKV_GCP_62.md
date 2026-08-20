# CKV_GCP_62: Bucket should log access

## Severity
**LOW** (score: 2.0/10)

Not enabling access logging on a storage bucket removes the audit trail needed to detect and investigate unauthorized reads, writes, or deletions of the bucket's objects.

## Summary
This check fails when a `google_storage_bucket` does not have an access-logging configuration (`logging` block with a non-empty `log_bucket`), meaning access to objects in the bucket is not being recorded.

## Applicability
- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_storage_bucket`
- **Check type:** resource check (Logging category)

## Why it matters
Cloud Storage access logs record every request made against a bucket — who accessed which object, when, from what source, and the outcome. Without this, there is no audit trail for object reads/writes/deletes, making it impossible to determine what was accessed in the event of a suspected data breach or insider-threat investigation, and to detect anomalous access patterns (e.g., unusual bulk downloads that could indicate exfiltration) after the fact. This is especially critical for buckets holding regulated data, credentials, or (as in the flagged example, `auth0_logs`) authentication/identity logs themselves, where the absence of access logging creates a monitoring blind spot on a security-sensitive data store.

## How Checkov evaluates this
The check (`CloudStorageLogging`) inspects the `logging` block on the bucket resource:
- **FAIL** if the `logging` block is absent entirely, or present but empty/has no `log_bucket` value.
- **PASS** if `logging[0].log_bucket` is present and non-empty.
- **UNKNOWN** if `log_bucket` is a computed/unresolved value at plan time (e.g., referencing an unapplied resource).

## Non-compliant example
```hcl
resource "google_storage_bucket" "auth0_logs" {
  name     = "app-auth0-logs"
  location = "US"
  # no logging block — access is not recorded
}
```

## Remediated example
```hcl
resource "google_storage_bucket" "access_logs" {
  name     = "app-storage-access-logs"
  location = "US"
  # this bucket must have appropriate IAM/uniform access controls of its own
}

resource "google_storage_bucket" "auth0_logs" {
  name     = "app-auth0-logs"
  location = "US"

  logging {
    log_bucket = google_storage_bucket.access_logs.name
  }
}
```

## Remediation steps
1. Create (or designate) a separate GCS bucket to serve as the log sink — do not log a bucket to itself (see CKV_GCP_63).
2. Add a `logging` block to the target bucket with `log_bucket` set to the log-sink bucket's name.
3. Restrict IAM permissions on the log-sink bucket tightly (write-only for the logging service, read limited to security/audit roles) since it will accumulate access records that are themselves sensitive.
4. Apply via `terraform apply` and re-scan with Checkov.
5. Set a lifecycle/retention policy on the log bucket appropriate to your compliance requirements.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudStorageLogging.py)
- [GCP Cloud Storage: Usage logs & storage logs](https://cloud.google.com/storage/docs/access-logs)
