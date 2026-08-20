# CKV_AWS_43: Ensure Kinesis Stream is securely encrypted
## Severity
**LOW** (score: 2.0/10)

A Kinesis stream without server-side (KMS) encryption stores in-flight data records unencrypted at rest, risking disclosure if the underlying storage or a misconfigured consumer is compromised.

## Summary
This check ensures Amazon Kinesis Data Streams have server-side encryption enabled using KMS.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Kinesis::Stream` (CloudFormation), `aws_kinesis_stream` (Terraform)

## Why it matters
Kinesis streams often carry high-volume, real-time data feeds — clickstreams, application logs, IoT telemetry, financial transactions — which can include PII or other sensitive information in transit through the stream's storage shards. Without server-side encryption, data at rest within the stream's internal storage is unencrypted, meaning any unauthorized access to the underlying AWS storage layer, misconfigured cross-account stream sharing, or an over-permissioned IAM policy that allows `kinesis:GetRecords` could expose plaintext data that should otherwise be protected by both IAM and KMS key policy layers. Server-side encryption with KMS adds a second, independent authorization boundary (the KMS key policy) that must also be satisfied to read data, which is valuable defense-in-depth.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` with an expected value of `"KMS"`:
- **CloudFormation:** inspects `Properties/StreamEncryption/EncryptionType` on `AWS::Kinesis::Stream` — **PASS** if the value is `KMS`, **FAIL** otherwise (including `NONE` or absent).
- **Terraform:** inspects the `encryption_type` argument on `aws_kinesis_stream` — **PASS** if `"KMS"`, **FAIL** if `"NONE"` or absent (Kinesis streams default to unencrypted).

## Non-compliant example
```hcl
resource "aws_kinesis_stream" "example" {
  name             = "example-stream"
  shard_count      = 1
  retention_period = 24
  # encryption_type not set -> defaults to NONE
}
```

## Remediated example
```hcl
resource "aws_kinesis_stream" "example" {
  name             = "example-stream"
  shard_count      = 1
  retention_period = 24
  encryption_type  = "KMS"
  kms_key_id       = "alias/aws/kinesis"  # or a customer-managed KMS key ARN
}
```

## Remediation steps
1. Set `encryption_type = "KMS"` on the `aws_kinesis_stream` resource (or `Properties/StreamEncryption/EncryptionType: KMS` in CloudFormation).
2. Specify `kms_key_id` — use the AWS-managed `alias/aws/kinesis` key for simplicity, or a customer-managed KMS key if you need custom key policies, cross-account access control, or key rotation auditing.
3. Ensure producer/consumer IAM roles have `kms:Decrypt`/`kms:GenerateDataKey` permissions on the chosen key, or data flow will break after enabling encryption.
4. This change can typically be applied to an existing stream without replacement (Kinesis supports enabling encryption in place), but verify with a plan review since producer/consumer permissions must be updated in tandem.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KinesisStreamEncryptionType.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/KinesisStreamEncryptionType.py)
- [AWS Kinesis Data Streams server-side encryption docs](https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html)
