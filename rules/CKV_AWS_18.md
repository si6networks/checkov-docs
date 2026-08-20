# CKV_AWS_18: Ensure the S3 bucket has access logging enabled
## Severity
**LOW** (score: 2.0/10)

Missing S3 access logging removes the audit trail needed to detect and investigate unauthorized access or data exfiltration from a bucket, which is a genuinely security-relevant monitoring gap on a commonly sensitive data store.

## Summary
This check requires that S3 buckets have server access logging configured, so that requests made against the bucket are recorded to a target logging bucket.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource/entity types:** `AWS::S3::Bucket` (CloudFormation); `aws_s3_bucket` and (via connection) `aws_s3_bucket_logging` (Terraform, graph-based check)
- **Check type:** resource attribute check (CloudFormation), graph-based connection/attribute check (Terraform)

## Why it matters
S3 access logs record every request made to a bucket — the requester, bucket/object, action, response status, and source IP — providing an audit trail independent of the requester's own logging. Without access logging, if a bucket is used to exfiltrate data, or an attacker with compromised credentials enumerates/downloads objects, there is no record inside AWS to reconstruct what happened, when, or from where. This significantly hampers incident response and forensic investigation and is a common gap flagged in security audits and compliance frameworks (PCI-DSS requirement 10, CIS AWS Foundations Benchmark) that mandate logging of access to systems storing sensitive data. Enabling access logging costs nothing but storage and provides a durable record that survives even if the bucket's own object versions are altered or deleted.

## How Checkov evaluates this
- **CloudFormation:** A `BaseResourceValueCheck` inspects `Properties/LoggingConfiguration` on `AWS::S3::Bucket`. It expects `ANY_VALUE` — if the `LoggingConfiguration` property block is present (regardless of exact contents), the check PASSES; if it's absent, the check FAILS.
- **Terraform:** This is implemented as a graph-based JSON policy (not Python). It evaluates to PASS if *either*:
  1. The `aws_s3_bucket` resource has a `logging` attribute block set directly (older Terraform AWS provider syntax), **or**
  2. The `aws_s3_bucket` resource is connected to (referenced by) a separate `aws_s3_bucket_logging` resource (the newer, decoupled resource style introduced in AWS provider v4+).
  
  If neither condition holds, the check FAILS.

## Non-compliant example
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-app-data-bucket"
  # no logging block, and no aws_s3_bucket_logging resource references this bucket
}
```

```yaml
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-app-data-bucket
      # LoggingConfiguration not set
```

## Remediated example
```hcl
resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-app-data-bucket-logs"
}

resource "aws_s3_bucket" "example" {
  bucket = "my-app-data-bucket"
}

resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}
```

```yaml
Resources:
  LogBucket:
    Type: AWS::S3::Bucket

  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-app-data-bucket
      LoggingConfiguration:
        DestinationBucketName: !Ref LogBucket
        LogFilePrefix: log/
```

## Remediation steps
1. Create (or designate) a separate S3 bucket to receive access logs, and ensure it grants the S3 log delivery group write permission (via bucket ACL or the `logging.s3.amazonaws.com` service).
2. In Terraform, add an `aws_s3_bucket_logging` resource pointing `bucket` at the source bucket and `target_bucket`/`target_prefix` at the logging bucket (preferred for AWS provider v4+), or use the inline `logging` block for older provider versions.
3. In CloudFormation, add a `LoggingConfiguration` property with `DestinationBucketName` and `LogFilePrefix`.
4. Avoid using the same bucket as both source and target to prevent a logging loop.
5. Consider setting a lifecycle policy on the log bucket to expire old logs and control storage costs.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/S3AccessLogs.py)
- [Checkov check source (Terraform graph check)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/S3BucketLogging.json)
- [AWS S3 server access logging documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)
