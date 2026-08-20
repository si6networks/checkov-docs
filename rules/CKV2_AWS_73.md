# CKV2_AWS_73: Ensure AWS SQS uses CMK not AWS default keys for encryption

## Severity
**LOW** (score: 2.0/10)

Using the AWS-managed default key instead of a customer-managed KMS key for SQS still encrypts data at rest but removes the ability to control access policy, rotation, and revocation of the encryption key independently, a weaker but not absent control.

## Summary
This check flags `aws_sqs_queue` resources that explicitly set `kms_master_key_id` to the AWS-managed default alias `alias/aws/sqs`, encouraging use of a customer-managed KMS key (CMK) instead.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_sqs_queue`

## Why it matters
SQS-managed server-side encryption using the AWS-managed key (`alias/aws/sqs`) does encrypt message data at rest, but the key is entirely controlled by AWS: you cannot define a custom key policy, cannot restrict which IAM principals may use it beyond what AWS's default policy allows, cannot enable/disable/rotate it on your own schedule, and cannot use it as an access-control boundary (e.g., granting decrypt only to a specific consumer role). This weakens the encryption-at-rest control as a genuine security boundary — it protects against physical media theft but does very little to enforce least-privilege among IAM principals in your own account, since the default key's policy is broad by design. A customer-managed key lets you scope exactly which roles/services can `Decrypt`/`GenerateDataKey`/`Encrypt`, add CloudTrail-visible key usage auditing tied to a key you control, and support requirements (many compliance frameworks — PCI-DSS, HIPAA, FedRAMP) that specifically call for customer-managed encryption keys rather than provider-default keys for sensitive data.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) with an `or` of two passing conditions on `aws_sqs_queue`:
1. `kms_master_key_id` **does not exist** at all (i.e., SQS-managed SSE, `SSE-SQS`, or no encryption configured — the check does not flag the *absence* of a key as a failure here).
2. `kms_master_key_id` **exists but is not equal** to `"alias/aws/sqs"`.

The check **FAILS** only in the specific case where `kms_master_key_id` is explicitly set to the literal value `alias/aws/sqs` — i.e., someone deliberately (or by copy-pasting boilerplate) pointed the queue at the AWS-managed default key alias instead of a customer-managed key or omitting the setting. Note this check is narrower than "ensure a CMK is used": it does not require `kms_master_key_id` to be set at all, only that *if* set, it isn't the specific AWS-managed alias.

## Non-compliant example
```hcl
resource "aws_sqs_queue" "orders" {
  name = "order-processing-queue"

  kms_master_key_id = "alias/aws/sqs"   # AWS-managed default key -> FAILS
}
```

## Remediated example
```hcl
resource "aws_kms_key" "sqs_cmk" {
  description             = "CMK for order-processing queue encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "sqs_cmk" {
  name          = "alias/order-processing-sqs"
  target_key_id = aws_kms_key.sqs_cmk.key_id
}

resource "aws_sqs_queue" "orders" {
  name = "order-processing-queue"

  kms_master_key_id = aws_kms_alias.sqs_cmk.name   # customer-managed key
}
```

## Remediation steps
1. Create a dedicated customer-managed KMS key (or reuse an appropriately scoped existing CMK) for the queue's encryption needs.
2. Set `kms_master_key_id` on the `aws_sqs_queue` to the CMK's key ID, ARN, or alias — not `alias/aws/sqs`.
3. Attach a key policy (see CKV2_AWS_64) that scopes `kms:Decrypt`/`kms:GenerateDataKey` to only the producer/consumer IAM roles that need to send/receive messages on this queue.
4. Consider setting `kms_data_key_reuse_period_seconds` to balance KMS API call costs against key-usage granularity — reusing data keys reduces `GenerateDataKey` calls but slightly widens the window a given data key protects.
5. Switching from the AWS-managed key to a CMK on an existing queue is an in-place, non-disruptive update (no message loss, no downtime), but verify IAM roles/consumers have `kms:Decrypt` on the new CMK before cutting over, or message consumption will fail with access-denied errors.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/SQSEncryptionCMK.json
- AWS docs: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
