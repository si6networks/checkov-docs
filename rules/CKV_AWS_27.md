# CKV_AWS_27: Ensure all data stored in the SQS queue is encrypted

## Severity
**LOW** (score: 2.0/10)

SQS queues frequently transport sensitive application data end-to-end, and leaving them unencrypted at rest means anyone with access to the underlying storage layer can read plaintext message bodies with no customer-controlled encryption boundary in the way.

## Summary
This check ensures that an SQS queue has server-side encryption enabled, either via SQS-managed encryption (SSE-SQS) or a customer-specified KMS key.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: resource `aws_sqs_queue`
- **CloudFormation**: resource type `AWS::SQS::Queue`

## Why it matters
SQS queues are frequently used to pass application messages between services, and message bodies can carry sensitive data — order details, user identifiers, event payloads, or serialized objects containing internal state. If a queue is left unencrypted, message content at rest is stored without the protection of a customer-influenced encryption boundary; anyone able to read the underlying storage (through misconfiguration, insider threat, or a bug elsewhere in AWS's control plane) would have direct access to plaintext data. Encryption at rest is table-stakes for any asynchronous messaging layer that might carry regulated data, and enabling it (whether via the simpler SQS-managed SSE or a full CMK) also closes a common gap that automated security scanning and compliance audits check for.

## How Checkov evaluates this
This check (unlike a plain attribute-presence check) has explicit logic in `scan_resource_conf` for Terraform, and a simple attribute check for CloudFormation:

**Terraform:**
1. If `sqs_managed_sse_enabled` is set and its first value is truthy → **PASS** (SQS-managed SSE is on).
   - Note the code comment: when `kms_master_key_id` is set, `sqs_managed_sse_enabled` is internally forced to false by the provider, so these two settings are mutually exclusive in practice.
2. Otherwise, if `kms_master_key_id` is set and non-empty → **PASS**.
3. If `kms_master_key_id` is set but empty/falsy → **FAIL**.
4. If neither attribute is set at all → **FAIL**.

**CloudFormation:** looks only at `Properties/KmsMasterKeyId` — any non-empty value passes (there is no CFN-native check for the newer `SqsManagedSseEnabled` property in this specific check implementation, so for CFN stacks, an explicit `KmsMasterKeyId` is what's evaluated).

## Non-compliant example
```hcl
resource "aws_sqs_queue" "orders" {
  name = "orders-queue"
  # neither sqs_managed_sse_enabled nor kms_master_key_id set
}
```

## Remediated example
```hcl
# Option A: SQS-managed SSE (simplest, no KMS key management needed)
resource "aws_sqs_queue" "orders" {
  name                    = "orders-queue"
  sqs_managed_sse_enabled = true
}

# Option B: Customer-managed KMS key (more control, key policy, audit trail)
resource "aws_sqs_queue" "orders_cmk" {
  name              = "orders-queue-cmk"
  kms_master_key_id = aws_kms_key.sqs.arn
}
```

## Remediation steps
1. Decide between SQS-managed SSE (`sqs_managed_sse_enabled = true`, zero-maintenance, AWS manages the key) or a CMK (`kms_master_key_id = <arn>`, full control over key policy/rotation/audit) based on your compliance requirements.
2. Add the chosen attribute to every `aws_sqs_queue` resource (or `KmsMasterKeyId` for CloudFormation).
3. If using a CMK, grant producers and consumers of the queue `kms:Decrypt`/`kms:GenerateDataKey` permissions in the key policy.
4. Do not set both `sqs_managed_sse_enabled` and `kms_master_key_id` simultaneously — the provider will resolve to using the KMS key and effectively disable the managed-SSE flag; pick one deliberately to avoid confusing configuration drift.
5. This is an in-place update; no resource replacement is required, though there may be a brief propagation delay for the encryption setting to take effect.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SQSQueueEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SQSQueueEncryption.py
- AWS documentation: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
