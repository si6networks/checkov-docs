# CKV_ALI_12: Ensure the OSS bucket has access logging enabled

## Severity
**LOW** (score: 2.0/10)

Missing access logging on an OSS bucket removes the audit trail needed to detect or investigate unauthorized access or exfiltration after the fact, a detective-control gap rather than a preventive one.

## Summary
This check ensures Alibaba Cloud OSS buckets have server access logging configured (a non-empty `logging` block), so that requests made against the bucket are recorded for audit and incident-response purposes.

## Applicability
**Checkov framework(s):** `terraform`

Terraform. Applies to the `alicloud_oss_bucket` resource, specifically its `logging` attribute (checked for any non-empty/present value via Checkov's `ANY_VALUE` sentinel).

## Why it matters
Without access logging, an OSS bucket produces no record of who accessed, uploaded, downloaded, or deleted objects and when. If a bucket is later found to have been breached, misused, or the source of a data leak, there is no forensic trail to determine the scope of unauthorized access, identify the responsible principal/IP, or establish a timeline of events — severely hampering incident response and any regulatory breach-notification obligations that require demonstrating what data was actually accessed. Access logs are also useful for detecting anomalous access patterns (unexpected geographic origins, unusual volumes of downloads) that can indicate an ongoing compromise or credential leak before a larger incident unfolds.

## How Checkov evaluates this
This is a Python check (`OSSBucketAccessLogs.py`) extending `BaseResourceValueCheck`. It inspects the `logging` key on the `alicloud_oss_bucket` resource and expects any present value (`ANY_VALUE` — i.e., the mere presence of a configured `logging` block, regardless of its specific target bucket/prefix, satisfies the check). If the `logging` block is absent entirely, the check fails.

## Non-compliant example
```hcl
resource "alicloud_oss_bucket" "app_data" {
  bucket = "company-app-data"
  acl    = "private"
  # no logging block - no access logs are recorded
}
```

## Remediated example
```hcl
resource "alicloud_oss_bucket" "log_target" {
  bucket = "company-oss-access-logs"
  acl    = "private"
}

resource "alicloud_oss_bucket" "app_data" {
  bucket = "company-app-data"
  acl    = "private"

  logging {
    target_bucket = alicloud_oss_bucket.log_target.id
    target_prefix = "app-data-logs/"
  }
}
```

## Remediation steps
1. Create (or designate) a separate OSS bucket dedicated to storing access logs, distinct from the bucket being logged, to avoid a logging feedback loop and to allow independent retention/access controls on the logs.
2. Add a `logging` block to each `alicloud_oss_bucket` resource specifying `target_bucket` and a `target_prefix` to organize logs per source bucket.
3. Restrict access to the logging target bucket tightly (private ACL, minimal RAM policy grants) since logs themselves can reveal sensitive access patterns and object key names.
4. Set a lifecycle rule on the log bucket to manage long-term storage costs while satisfying your organization's log retention/compliance requirements.
5. Feed the logs into a centralized log analysis or SIEM pipeline where feasible, so anomalous access patterns can be detected proactively rather than only reviewed after an incident.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/OSSBucketAccessLogs.py
