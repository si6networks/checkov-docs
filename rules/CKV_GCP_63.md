# CKV_GCP_63: Bucket should not log to itself

## Severity
**LOW** (score: 2.0/10)

A bucket logging to itself is mainly a logging-integrity/hygiene defect (an attacker who can modify bucket contents can also tamper with its own logs), but it does not itself expose data or grant access, so its direct exploitability is limited.

## Summary
This check fails when a `google_storage_bucket`'s `logging.log_bucket` attribute points back to the same bucket, i.e., the bucket is configured to write its own access logs into itself.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (GCP provider)
- **Resource type:** `google_storage_bucket`
- **Check type:** resource check (Logging category)

## Why it matters
If a bucket logs access events to itself, several problems follow. First, it creates a feedback loop: writing log objects into the bucket generates more access events, which get logged, generating more objects — inflating storage costs and log volume unnecessarily. Second, and more importantly from a security standpoint, it undermines the integrity and separation-of-duties principle behind audit logging: anyone with write/delete access to the bucket's *data* also has the same access to its *log records*, meaning an attacker (or malicious insider) who compromises the bucket can tamper with or delete the very logs that would reveal their access — defeating the purpose of the audit trail. Logs should always be written to a separate, more tightly access-controlled destination so that compromising the source doesn't automatically compromise its own audit record.

## How Checkov evaluates this
The check (`CloudStorageSelfLogging`) reads the bucket's own `name` attribute and its `logging[0].log_bucket` value:
- **FAIL** if `logging` is configured and `log_bucket == name` (the bucket logs to itself).
- **PASS** if `logging` is configured and `log_bucket != name` (logs go elsewhere).
- **UNKNOWN** if no `logging` block is present at all, or `log_bucket` is a computed/unresolved value at plan time.

Note this check only guards against the self-referential misconfiguration; it does not by itself confirm that logging is enabled (see CKV_GCP_62 for that).

## Non-compliant example
```hcl
resource "google_storage_bucket" "app_data" {
  name     = "app-data-bucket"
  location = "US"

  logging {
    log_bucket = "app-data-bucket"  # same as this bucket's own name — logs to itself
  }
}
```

## Remediated example
```hcl
resource "google_storage_bucket" "access_logs" {
  name     = "app-data-bucket-access-logs"
  location = "US"
}

resource "google_storage_bucket" "app_data" {
  name     = "app-data-bucket"
  location = "US"

  logging {
    log_bucket = google_storage_bucket.access_logs.name
  }
}
```

## Remediation steps
1. Provision a dedicated, separate bucket to act as the logging destination.
2. Update `logging.log_bucket` on the source bucket to reference the separate bucket's name (never its own `name`).
3. Apply tighter IAM restrictions to the log-destination bucket than to the source bucket, ideally limiting write access to the GCS logging service account and read access to security/audit personnel only.
4. Apply via `terraform apply` and re-scan with Checkov.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudStorageSelfLogging.py)
- [GCP Cloud Storage: Access logs & storage logs](https://cloud.google.com/storage/docs/access-logs)
