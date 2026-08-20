# CKV_AWS_144: Ensure that S3 bucket has cross-region replication enabled
## Severity
**LOW** (score: 2.0/10)

This check addresses data durability/disaster-recovery posture (cross-region replication), not a direct confidentiality, integrity, or access-control exposure, so it is best treated as an availability hygiene control rather than a high-impact security gap.

## Summary
This check verifies that an S3 bucket has a cross-region (or same-region) replication rule configured and enabled, so objects are automatically copied to a second bucket.

## Applicability
Terraform only. Applies to `aws_s3_bucket` (legacy inline `replication_configuration` block) and the standalone `aws_s3_bucket_replication_configuration` resource (introduced with the AWS provider v4 refactor of the S3 bucket resource).

## Why it matters
Without replication, a bucket's objects exist in only one AWS region (or, for same-region replication, only in the original storage tier/account). If that region experiences an outage, or the bucket/account is compromised and objects are deleted or corrupted (accidentally or maliciously, e.g. via a compromised IAM credential running a mass-delete), there is no independent copy to fail over to or recover from. Cross-region replication (CRR) is a core building block for disaster recovery, data residency/backup requirements, and reducing the blast radius of a single-region or single-account incident. It also supports compliance regimes that require geographically separated backups.

## How Checkov evaluates this
This is a graph-based check (JSON policy), not a plain attribute check on one resource. It passes if either:
1. The `aws_s3_bucket` resource has an inline `replication_configuration.rules.*.status` attribute equal to `"Enabled"`, OR
2. The `aws_s3_bucket` resource is connected (via `bucket = aws_s3_bucket.x.id` or similar reference) to an `aws_s3_bucket_replication_configuration` resource whose `rule.*.status` attribute equals `"Enabled"`.

If neither condition is satisfied — no replication configuration at all, or a replication rule present but with `status = "Disabled"` — the check fails.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
}
```

## Remediated example
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled" # required for replication
  }
}

resource "aws_iam_role" "replication" {
  name               = "s3-replication-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_s3_bucket" "data_replica" {
  bucket   = "my-company-data-bucket-replica"
  provider = aws.us-west-2
}

resource "aws_s3_bucket_replication_configuration" "data" {
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "replicate-all"
    status = "Enabled"       # <-- required for the check to pass

    destination {
      bucket = aws_s3_bucket.data_replica.arn
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}
```

## Remediation steps
1. Enable versioning on both the source and destination buckets (a hard AWS prerequisite for replication).
2. Create (or reuse) a destination bucket, ideally in a different region for true disaster-recovery coverage.
3. Create an IAM role that grants S3 permission to read from the source and write to the destination bucket.
4. Add an `aws_s3_bucket_replication_configuration` resource (or the inline `replication_configuration` block on older provider versions) referencing that role and destination, with `rule { status = "Enabled" }`.
5. Note replication only applies to objects created after the configuration is enabled unless you run an S3 Batch Operations replication job for existing objects.
6. Consider replication time control (RTC) if you need an SLA on replication latency.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3BucketReplicationConfiguration.json
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html
