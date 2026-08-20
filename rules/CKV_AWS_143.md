# CKV_AWS_143: Ensure that S3 bucket has lock configuration enabled by default

## Severity
**LOW** (score: 2.0/10)

Without Object Lock (WORM), objects such as backups, audit logs, or compliance records can be deleted or overwritten by any sufficiently privileged or compromised principal, undermining tamper-resistance guarantees though not exposing data itself.

## Summary
This check requires S3 buckets to configure `object_lock_configuration` with `object_lock_enabled = "Enabled"`, turning on S3 Object Lock (WORM — write-once-read-many) protection so objects cannot be deleted or overwritten for a configured retention period.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_s3_bucket`

## Why it matters
Without Object Lock, any principal with sufficient S3 permissions (a legitimate user with excessive permissions, a compromised IAM credential, or ransomware-style malware that has obtained write/delete access) can overwrite or permanently delete objects in the bucket — including compliance records, backups, audit logs, or financial data that may have legal retention requirements. Object Lock in compliance or governance mode prevents deletion/overwrite for a fixed retention window even by the root account (in compliance mode) or by users without special permissions (in governance mode), providing a strong technical control against both accidental data loss and deliberate tampering — this is frequently required for financial, healthcare, and legal records subject to regulations such as SEC 17a-4, FINRA, or similar records-retention rules.

## How Checkov evaluates this
The check (`S3BucketObjectLock`, `BaseResourceCheck`) inspects `object_lock_configuration`:
- If `object_lock_configuration` is absent, or present but not a well-formed dict block, the result is **UNKNOWN** (Checkov cannot determine intent — object lock can only be set at bucket creation time in Terraform, so an absent block might mean it was intentionally omitted or configured out of band).
- If the block is present, it reads `object_lock_enabled` inside it: **PASS** if the value is `"Enabled"` (as either a plain string or a single-element list `["Enabled"]`, accounting for how Terraform config is parsed); **FAIL** for any other value (e.g., a typo, or an explicit non-"Enabled" setting).

## Non-compliant example
```hcl
resource "aws_s3_bucket" "records" {
  bucket = "compliance-records-bucket"
  # object_lock_configuration not set -> result is UNKNOWN (should be set explicitly for compliance-sensitive buckets)
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "records" {
  bucket = "compliance-records-bucket"

  object_lock_enabled = true   # required at bucket creation time

  object_lock_configuration {
    rule {
      default_retention {
        mode = "COMPLIANCE"
        days = 365
      }
    }
  }
}

# Note: some provider versions require this nested attribute instead:
#   object_lock_configuration {
#     object_lock_enabled = "Enabled"
#     rule { ... }
#   }
```

## Remediation steps
1. Enable Object Lock at bucket creation using the top-level `object_lock_enabled = true` argument (required by newer AWS provider versions) together with a nested `object_lock_configuration` block specifying a default retention rule (`mode = "COMPLIANCE"` or `"GOVERNANCE"`, plus `days` or `years`).
2. **Important:** Object Lock can only be enabled when the bucket is created — it cannot be turned on for an existing bucket via `terraform apply`. Enabling it requires creating a new bucket and migrating data (`aws s3 sync` or S3 Batch Operations / replication), since this is a resource-replacement-class change.
3. Object Lock requires bucket versioning to be enabled; ensure `aws_s3_bucket_versioning` (or the equivalent inline block for older provider versions) is configured.
4. Choose retention mode carefully: `COMPLIANCE` mode cannot be shortened or removed by any user, including the AWS account root user, for the duration of the retention period — make sure this matches an actual regulatory or business retention requirement before applying it broadly.
5. Only apply Object Lock to buckets that genuinely need immutable records; it is not appropriate for buckets with frequently-updated or transient objects.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/S3BucketObjectLock.py)
- [AWS: Using S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
