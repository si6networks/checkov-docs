# CKV_AWS_77: Ensure Athena Database is encrypted at rest (default is unencrypted)
## Severity
**MEDIUM** (score: 5.0/10)

An unencrypted Athena database leaves query results and underlying data at rest unprotected, risking disclosure of potentially sensitive analytics data if storage or backups are accessed improperly.

## Summary
This check fails when an AWS Athena database (the S3-backed query result/catalog store) does not have an encryption configuration set, since Athena databases are **unencrypted by default**.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_athena_database`
- **Check type:** resource

## Why it matters
Athena queries data in S3 and writes query results (which can contain the exact rows/columns returned by a query, including sensitive fields) to an S3 location associated with the database. Without encryption configuration on the Athena database, those result sets are stored in plaintext, meaning anyone with read access to the underlying S3 results bucket — including via a future misconfiguration, an over-permissioned IAM role, or bucket policy drift — can read query output directly, bypassing whatever data protections exist at the source dataset level. Since Athena is often used to run ad hoc analytical queries over data lakes containing customer or financial data, unencrypted result storage creates a persistent, easily-overlooked copy of sensitive data outside the primary access-controlled dataset.

## How Checkov evaluates this
The check (`AthenaDatabaseEncryption.py`) extends `BaseResourceValueCheck` with expected value `ANY_VALUE`. It inspects the nested path `encryption_configuration/[0]/encryption_option` on `aws_athena_database`. The check passes as soon as any value (e.g. `SSE_S3`, `SSE_KMS`, `CSE_KMS`) is set for `encryption_option`; it fails if the `encryption_configuration` block is missing entirely or `encryption_option` is not set.

## Non-compliant example
```hcl
resource "aws_athena_database" "analytics" {
  name   = "analytics_db"
  bucket = aws_s3_bucket.athena_results.id
}
```

## Remediated example
```hcl
resource "aws_athena_database" "analytics" {
  name   = "analytics_db"
  bucket = aws_s3_bucket.athena_results.id

  encryption_configuration {
    encryption_option = "SSE_KMS"
    kms_key           = aws_kms_key.athena.arn
  }
}
```

## Remediation steps
1. Add an `encryption_configuration` block to the `aws_athena_database` resource.
2. Set `encryption_option` to `SSE_S3` (S3-managed keys, simplest) or `SSE_KMS`/`CSE_KMS` (customer-managed KMS key, for tighter access control and audit via CloudTrail key usage).
3. If using `SSE_KMS`/`CSE_KMS`, provide `kms_key` and ensure the Athena/Glue execution role and querying principals have `kms:Decrypt`/`kms:GenerateDataKey` permissions on that key.
4. Note: changing encryption settings on an Athena database with existing query result data may require recreating the results bucket location or reconfiguring the workgroup's result configuration — test in a non-production workgroup first.
5. Also review the associated Athena Workgroup configuration (see CKV_AWS_82) to ensure it enforces this encryption setting so it can't be overridden per-query.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AthenaDatabaseEncryption.py)
- [Amazon Athena encryption at rest](https://docs.aws.amazon.com/athena/latest/ug/encryption.html)
