# CKV_AWS_209: Ensure MQ broker encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

An MQ broker without CMK-based encryption at rest leaves queued and stored messages -- which often carry sensitive application payloads -- unprotected against exposure via underlying storage access.

## Summary
Ensures that an Amazon MQ broker specifies a customer-managed KMS key (CMK) for at-rest encryption, rather than relying on the AWS-managed default key.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_mq_broker` — inspects `encryption_options[0].kms_key_id`.

## Why it matters
Amazon MQ brokers persist message data (for durable queues/topics) to underlying storage, which is always encrypted at rest, but by default with an AWS-managed key unless a CMK is specified. Message brokers frequently carry business-critical or sensitive payloads (order data, financial transactions, PII in event payloads) in transit through durable storage. Relying on the default key rather than a CMK means:
- You cannot scope a dedicated key policy restricting exactly which IAM principals/accounts may decrypt the broker's persisted data.
- You lose the ability to generate isolated CloudTrail audit events (`kms:Decrypt`, `kms:GenerateDataKey`) tied to a specific key you control, which is important for detecting anomalous decrypt activity against broker storage.
- You cannot independently disable/schedule deletion of the encryption key to cryptographically revoke access to broker data during an incident.
- Compliance frameworks (PCI-DSS, HIPAA, FedRAMP) that mandate customer-managed encryption keys for data governed by those regimes are not satisfied by the AWS-managed default key alone.

## How Checkov evaluates this
`MQBrokerEncryptedWithCMK` is a `BaseResourceValueCheck` expecting `ANY_VALUE` on the nested attribute `encryption_options/[0]/kms_key_id`:
- If `encryption_options[0].kms_key_id` is set to any value → PASS.
- If `encryption_options` is absent, or present without a `kms_key_id` → FAIL.

## Non-compliant example
```hcl
resource "aws_mq_broker" "orders_broker" {
  broker_name        = "orders-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.17.6"
  host_instance_type = "mq.t3.micro"
  deployment_mode    = "SINGLE_INSTANCE"

  encryption_options {
    use_aws_owned_key = true   # FAILS CKV_AWS_209 - no CMK reference
  }

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediated example
```hcl
resource "aws_kms_key" "mq_cmk" {
  description         = "CMK for Amazon MQ broker encryption"
  enable_key_rotation = true
}

resource "aws_mq_broker" "orders_broker" {
  broker_name        = "orders-broker"
  engine_type        = "ActiveMQ"
  engine_version     = "5.17.6"
  host_instance_type = "mq.t3.micro"
  deployment_mode    = "SINGLE_INSTANCE"

  encryption_options {
    use_aws_owned_key = false
    kms_key_id        = aws_kms_key.mq_cmk.arn   # fix
  }

  user {
    username = "admin"
    password = var.mq_password
  }
}
```

## Remediation steps
1. Create a dedicated customer-managed KMS key (with rotation enabled) for MQ broker encryption.
2. Set `encryption_options.kms_key_id` to that CMK's ARN and set `use_aws_owned_key = false`.
3. Grant the Amazon MQ service and any consuming application roles `kms:Decrypt`/`kms:GenerateDataKey`/`kms:DescribeKey` permissions in the CMK's key policy.
4. Changing `encryption_options` on an existing broker requires replacement — plan a maintenance window and message drain/migration strategy since encryption configuration cannot be modified in place on a running broker.
5. Ensure the CMK exists in the same region as the broker.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MQBrokerEncryptedWithCMK.py
- AWS docs: https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/data-protection.html
