# CKV_AWS_119: Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK

## Severity
**LOW** (score: 2.0/10)

DynamoDB tables without a customer-managed KMS key rely on default encryption with no customer control over key rotation/access policy, weakening at-rest protection for what is often sensitive application data.

## Summary
Fails when a DynamoDB table's server-side encryption is not explicitly enabled with a customer-managed KMS key (CMK) ARN specified.

## Applicability
- **Terraform**: `aws_dynamodb_table` resource.
- **CloudFormation**: `AWS::DynamoDB::Table`.

## Why it matters
DynamoDB encrypts all tables at rest by default using an AWS-owned key, and can optionally use an AWS-managed key (`alias/aws/dynamodb`) or a customer-managed KMS key (CMK). Using a customer-managed CMK, rather than the default AWS-owned key, matters because:
- **Access control granularity**: A CMK's key policy can be scoped to specific IAM principals, enabling separation of duties between who can administer the key and who can use it to decrypt data — impossible with an AWS-owned key, which customers cannot control access to at all.
- **Auditability**: Every use of a customer-managed CMK (encrypt/decrypt/generate-data-key calls) is logged individually in CloudTrail with the specific key ARN, supporting compliance requirements for demonstrating control over encryption keys.
- **Revocation/key rotation control**: Customers can disable, rotate, or delete a CMK to immediately cut off access to the encrypted data (e.g. during an incident or offboarding), a capability not available with AWS-owned keys.
- **Regulatory requirements**: Frameworks like PCI-DSS, HIPAA, and FedRAMP often specifically require customer control over encryption keys protecting regulated data, which AWS-owned keys do not satisfy.

Without a CMK, encryption is still occurring, but the customer has no independent control over the key's lifecycle or access policy, weakening the practical security and compliance value of "encryption at rest."

## How Checkov evaluates this
- **Terraform**: Inspects the `server_side_encryption` block. Passes only if `enabled == [True]` AND `kms_key_arn` is present (non-null). Fails if the block is missing entirely, `enabled` is false, or `kms_key_arn` is not set (meaning either SSE is off, or it's using the default/AWS-managed key without an explicit CMK reference).
- **CloudFormation**: Inspects `Properties/SSESpecification`. Passes only if `SSEEnabled` is truthy AND `KMSMasterKeyId` is set. Fails otherwise.

## Non-compliant example
```hcl
resource "aws_dynamodb_table" "bad" {
  name         = "orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "OrderId"

  attribute {
    name = "OrderId"
    type = "S"
  }

  # No server_side_encryption block -> uses AWS owned key by default,
  # or server_side_encryption { enabled = true } without kms_key_arn also fails.
}
```

## Remediated example
```hcl
resource "aws_kms_key" "dynamodb" {
  description         = "CMK for DynamoDB table encryption"
  enable_key_rotation = true
}

resource "aws_dynamodb_table" "good" {
  name         = "orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "OrderId"

  attribute {
    name = "OrderId"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb.arn
  }
}
```

## Remediation steps
1. Create a customer-managed KMS key dedicated (or shared appropriately) for DynamoDB table encryption, with `enable_key_rotation = true` for automatic annual key rotation.
2. Add a `server_side_encryption` block to the table with `enabled = true` and `kms_key_arn` set to that CMK's ARN.
3. Define a key policy that grants the DynamoDB service and the specific IAM roles/users needing table access the required `kms:Decrypt`, `kms:GenerateDataKey`, and `kms:DescribeKey` permissions, while restricting administrative actions to a smaller set of principals.
4. Note: switching from the default/AWS-managed key to a CMK on an existing table is an in-place modification (no replacement/downtime), but confirm all consumers' IAM roles have the necessary KMS permissions before the change takes effect, or they will start receiving access-denied errors on table operations.
5. Budget for KMS API request costs — customer-managed CMK usage for DynamoDB incurs KMS request charges beyond the free AWS-owned/managed key options, roughly proportional to table read/write throughput.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DynamoDBTablesEncrypted.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DynamoDBTablesEncrypted.py
- AWS documentation: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html
