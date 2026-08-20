# CKV_AWS_240: Ensure Kinesis Firehose delivery stream is encrypted

## Severity
**LOW** (score: 2.0/10)

Without server-side encryption, records buffered in the Firehose delivery stream — which may include PII or other sensitive payloads — are held unencrypted at rest within the service.

## Summary
This check ensures that an `aws_kinesis_firehose_delivery_stream` resource has server-side encryption (SSE) enabled, so data buffered within the Firehose delivery stream is encrypted at rest.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_kinesis_firehose_delivery_stream`

## Why it matters
Kinesis Data Firehose buffers records in-flight before delivering them to a destination (S3, Redshift, OpenSearch, Splunk, etc.). Without server-side encryption enabled, data sitting in that internal buffer — which can include application logs, clickstream data, IoT telemetry, or any other stream payload, potentially containing PII or sensitive business data — is stored unencrypted within the service, relying solely on AWS's underlying infrastructure security rather than a customer-controlled encryption layer. This weakens the defense-in-depth posture for data in the pipeline and can fail compliance requirements that mandate encryption at rest for all data stores handling regulated data (e.g. PCI-DSS, HIPAA), even for transient/buffered storage. Encrypting the delivery stream is a low-cost control that closes this gap without affecting how producers write to or consumers read from the stream.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` (not a simple value check) with special-cased logic:
- If the resource has a `kinesis_source_configuration` block (meaning the Firehose stream's source is itself a Kinesis Data Stream, not direct-PUT), the check returns **UNKNOWN** — server-side encryption should *not* be configured on the Firehose delivery stream in this scenario, since encryption is instead handled by the source Kinesis stream, so Checkov cannot definitively call this a pass or fail without more context.
- Otherwise, it inspects `server_side_encryption[0].enabled`:
  - **PASS** if `server_side_encryption` is present and `enabled == [True]` (i.e., set to `true`).
  - **FAIL** if `server_side_encryption` is absent, or present but not enabled.

## Non-compliant example
```hcl
resource "aws_kinesis_firehose_delivery_stream" "logs" {
  name        = "app-logs-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.logs.arn
  }
}
```

## Remediated example
```hcl
resource "aws_kinesis_firehose_delivery_stream" "logs" {
  name        = "app-logs-stream"
  destination = "extended_s3"

  server_side_encryption {
    enabled = true
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.logs.arn
  }
}
```

## Remediation steps
1. Add a `server_side_encryption` block with `enabled = true` to the `aws_kinesis_firehose_delivery_stream` resource — unless the stream's source is a Kinesis Data Stream (`kinesis_source_configuration` present), in which case encryption should instead be configured on the source stream itself.
2. To use a customer-managed KMS key rather than the AWS-owned default, also set `key_type = "CUSTOMER_MANAGED_CMK"` and `key_arn` within the same block (see CKV_AWS_241 for the stricter CMK-specific check).
3. Confirm the Firehose IAM role has any necessary `kms:GenerateDataKey`/`kms:Decrypt` permissions if a CMK is used.
4. Enabling SSE on an existing delivery stream is applied via an in-place update in AWS and does not require deleting/recreating the stream.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KinesisFirehoseDeliveryStreamSSE.py)
- [Amazon Kinesis Data Firehose: Data protection / server-side encryption](https://docs.aws.amazon.com/firehose/latest/dev/encryption.html)
