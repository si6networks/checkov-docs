# CKV_AWS_185: Ensure Kinesis Stream is encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

Kinesis streams frequently carry live application/event data, and while this check only enforces CMK usage (not encryption presence), losing customer control over the encryption key for in-flight sensitive data streams is a moderate risk.

## Summary
This check requires that an `aws_kinesis_stream` resource specify a customer-managed KMS key (`kms_key_id`) for server-side encryption instead of the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_kinesis_stream`
- **Check type:** resource (attribute-value check)

## Why it matters
Kinesis Data Streams often carry real-time event data — clickstreams, transaction events, application logs, IoT telemetry — that can include PII or business-sensitive information in transit through the stream's storage layer. Encrypting the stream with the AWS-managed key (`alias/aws/kinesis`) protects data at rest but gives your organization no control over the key's policy, no ability to restrict decrypt access to specific producer/consumer IAM roles beyond what AWS's default policy allows, and no way to revoke access instantly. A customer-managed key lets you scope decrypt/encrypt permissions precisely to the producer and consumer applications, rotate the key on your schedule, and audit every use via CloudTrail — important when the stream is part of a data pipeline subject to compliance requirements (e.g., financial transaction streams under PCI-DSS).

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the `kms_key_id` attribute of `aws_kinesis_stream`. It expects `ANY_VALUE` — any non-empty value passes. If `kms_key_id` is absent, the check FAILS (this occurs whether `encryption_type` is unset or set to `NONE`/left to default, and also if `encryption_type = "KMS"` is set but no key id is supplied — the check simply verifies the attribute's presence).

## Non-compliant example
```hcl
resource "aws_kinesis_stream" "example" {
  name             = "events-stream"
  shard_count      = 2
  encryption_type  = "KMS"
  # kms_key_id not set -- falls back to AWS-managed alias/aws/kinesis
}
```

## Remediated example
```hcl
resource "aws_kms_key" "kinesis" {
  description             = "CMK for Kinesis stream encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kinesis_stream" "example" {
  name            = "events-stream"
  shard_count     = 2
  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis.arn  # customer managed key
}
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy scoped to the specific producer and consumer IAM roles/applications for the stream.
2. Set `encryption_type = "KMS"` and `kms_key_id` on the `aws_kinesis_stream` resource.
3. Grant the CMK's key policy `kms:GenerateDataKey` and `kms:Decrypt` to producers and consumers respectively (Kinesis uses envelope encryption per record).
4. Enabling/changing encryption on an existing stream is a mutable, non-disruptive operation via `aws kinesis start-stream-encryption` / updating the Terraform resource in place — no data loss, though there is a brief propagation period across shards.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KinesisStreamEncryptedWithCMK.py)
- [AWS Kinesis Data Streams server-side encryption documentation](https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html)
