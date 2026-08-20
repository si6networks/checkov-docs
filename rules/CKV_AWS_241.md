# CKV_AWS_241: Ensure that Kinesis Firehose Delivery Streams are encrypted with CMK

## Severity
**LOW** (score: 2.0/10)

Encryption is already enabled by CKV_AWS_240's control; using the AWS-owned key instead of a customer-managed key only narrows key-level access control, auditability, and revocation, a smaller incremental risk than encryption being absent entirely.

## Summary
This check ensures that an `aws_kinesis_firehose_delivery_stream` uses server-side encryption enabled with a customer-managed KMS key (CMK), including a valid key ARN, rather than relying on the AWS-owned default key or leaving encryption disabled.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_kinesis_firehose_delivery_stream`

## Why it matters
This check goes a step further than CKV_AWS_240 (which only requires SSE to be turned on): it requires that encryption specifically use a **customer-managed** KMS key. With the AWS-owned default key, you have no ability to define a custom key policy, no ability to restrict which IAM principals may decrypt buffered stream data, no independent audit trail for key usage tied specifically to this stream, and no ability to revoke or rotate the key on your own schedule. For Firehose streams handling regulated or sensitive data (PII, financial transactions, health data), compliance frameworks frequently require demonstrable, customer-controlled key management — an auditor asking "who can decrypt this data, and can you prove it, and can you revoke it" cannot be satisfactorily answered when the default AWS-owned key is in use. A CMK also lets you scope access precisely: only the Firehose delivery role and specific downstream consumers get `kms:Decrypt`, and that grant can be revoked independently of any other resource's encryption in the account.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` with the following logic:
- If `kinesis_source_configuration` is present (the stream sources from a Kinesis Data Stream rather than direct-PUT), returns **UNKNOWN** — encryption should be handled at the source stream, not here.
- Otherwise, requires **all** of the following to be true for a **PASS**:
  1. `server_side_encryption[0].enabled == [True]`
  2. `server_side_encryption[0].key_type == ["CUSTOMER_MANAGED_CMK"]`
  3. `server_side_encryption[0].key_arn` is present and non-empty
- **FAIL** is returned if `server_side_encryption` is missing entirely, if `enabled` is not true, if `key_type` is not `CUSTOMER_MANAGED_CMK` (e.g. left as the default AWS-owned key type), or if `key_arn` is missing/empty.

## Non-compliant example
```hcl
resource "aws_kinesis_firehose_delivery_stream" "logs" {
  name        = "app-logs-stream"
  destination = "extended_s3"

  server_side_encryption {
    enabled = true
    # key_type defaults to AWS_OWNED_CMK; no key_arn supplied
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.logs.arn
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "firehose_key" {
  description = "CMK for Firehose delivery stream encryption"
}

resource "aws_kinesis_firehose_delivery_stream" "logs" {
  name        = "app-logs-stream"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.firehose_key.arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.logs.arn
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key intended for Firehose stream encryption.
2. Set `server_side_encryption.key_type = "CUSTOMER_MANAGED_CMK"` and `server_side_encryption.key_arn = <your key ARN>` on the delivery stream, alongside `enabled = true`.
3. Grant the Firehose delivery IAM role (`role_arn`) `kms:GenerateDataKey` and `kms:Decrypt` permissions in the CMK's key policy.
4. If the stream sources from a Kinesis Data Stream (`kinesis_source_configuration` present), apply CMK encryption to the source stream instead — this check will report UNKNOWN in that scenario rather than fail.
5. Updating encryption settings on an existing Firehose stream is an in-place update; no data loss occurs, but ensure the consuming role has decrypt rights on the new CMK before the change is applied to avoid delivery failures.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KinesisFirehoseDeliveryStreamUsesCMK.py)
- [Amazon Kinesis Data Firehose: Data protection / server-side encryption](https://docs.aws.amazon.com/firehose/latest/dev/encryption.html)
