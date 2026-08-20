# CKV_AWS_26: Ensure all data stored in the SNS topic is encrypted

## Severity
**MEDIUM** (score: 5.0/10)

SNS topics routinely carry sensitive payloads (PII, alerts, cross-service events), and without server-side encryption those messages sit at rest without a customer-controlled protection or audit boundary, exposing plaintext data to anyone who reaches the underlying storage layer.

## Summary
This check ensures that an SNS topic has server-side encryption (SSE) enabled by specifying a KMS key, so that messages published to and stored in the topic are encrypted at rest.

## Applicability
- **Terraform**: resource `aws_sns_topic`
- **CloudFormation**: resource type `AWS::SNS::Topic`

## Why it matters
SNS topics can carry sensitive payloads — application events, notifications containing PII, alerting data, webhook payloads, or cross-service messages. Without server-side encryption, message content at rest (in SNS's backing storage) is not protected by a customer-controlled key, and an attacker or over-privileged principal with access to the underlying storage layer (or an insufficiently scoped IAM/resource policy) has a larger blast radius if they can read message data directly. Using a KMS key (ideally a customer-managed key, CMK) also lets you enforce key policies, rotation, and audit trails via CloudTrail on who used the key to decrypt, giving you an additional layer of access control and forensic visibility beyond IAM alone.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects a single attribute for the presence of any non-empty value (`ANY_VALUE`):
- **Terraform**: looks at `kms_master_key_id` on `aws_sns_topic`. If it is set to any value, the check **PASSES**; if absent or empty, it **FAILS**.
- **CloudFormation**: looks at `Properties/KmsMasterKeyId` on `AWS::SNS::Topic`. Same logic — presence of any value passes.

Note: the check only verifies that *a* KMS key ID is set — it does not distinguish between the AWS-managed `alias/aws/sns` key and a customer-managed key, so simply pointing to the default AWS-managed key will also pass.

## Non-compliant example
```hcl
resource "aws_sns_topic" "alerts" {
  name = "app-alerts"
}
```

## Remediated example
```hcl
resource "aws_sns_topic" "alerts" {
  name              = "app-alerts"
  kms_master_key_id = "alias/aws/sns"   # or the ARN/alias of a customer-managed CMK
}
```

## Remediation steps
1. Add the `kms_master_key_id` argument to every `aws_sns_topic` resource (Terraform) or `KmsMasterKeyId` property (CloudFormation).
2. For stronger control (key policy, rotation schedule, audit granularity), create a dedicated `aws_kms_key`/`AWS::KMS::Key` and reference its ARN or alias instead of the AWS-managed `alias/aws/sns` key.
3. Ensure the IAM principals that publish/subscribe to the topic have `kms:Decrypt`/`kms:GenerateDataKey` permissions on the chosen key, or message delivery to subscribers (e.g., SQS, Lambda) may fail.
4. If subscribers are SQS queues, confirm the SQS queue's own encryption/key policy allows decryption of the SNS-encrypted payload.
5. This change does not require resource replacement; it can be applied via a Terraform update in place.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SNSTopicEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SNSTopicEncryption.py
