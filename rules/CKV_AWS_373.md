# CKV_AWS_373: Ensure Bedrock Agent is encrypted with a CMK

## Severity
**MEDIUM** (score: 5.0/10)

Relying on AWS-owned default encryption instead of a customer-managed key removes independent key rotation, CloudTrail decrypt auditing, and crypto-shredding revocation for agent data that may embed proprietary prompts or business logic, a control-hardening gap rather than a direct exposure.

## Summary
This check ensures that an Amazon Bedrock Agent resource specifies a customer-managed KMS key (CMK) to encrypt the agent's data, rather than relying on AWS-managed default encryption.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::Bedrock::Agent` (property `CustomerEncryptionKeyArn`), `aws_bedrockagent_agent` (attribute `customer_encryption_key_arn`)

## Why it matters
Bedrock Agents orchestrate calls to foundation models along with associated configuration, session state, and potentially sensitive prompt/instruction data (system prompts, knowledge-base references, action-group definitions that may embed internal API schemas or business logic). By default, Bedrock encrypts this at rest using an AWS-owned key, which your organization cannot audit, rotate on its own schedule, or revoke access to independently. Specifying a customer-managed KMS key (a CMK) restores those controls: you get CloudTrail visibility into every encrypt/decrypt operation against the agent's data, the ability to define a key policy that scopes exactly which principals/services may use the key, and the ability to disable/schedule deletion of the key to immediately and provably cut off access to the underlying data (a "crypto-shredding" capability AWS-owned keys don't offer). This matters particularly for agents whose instructions, session data, or knowledge base integration reveal proprietary business logic or handle regulated data categories.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) using `ANY_VALUE` as the expected value — it only verifies that `Properties/CustomerEncryptionKeyArn` (`customer_encryption_key_arn`) is set to *some* non-empty value, not a specific key ARN. If the field is absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_bedrockagent_agent" "support_agent" {
  agent_name              = "customer-support-agent"
  agent_resource_role_arn = aws_iam_role.bedrock_agent.arn
  foundation_model         = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction              = "You are a helpful customer support assistant."
  # No customer_encryption_key_arn -> relies on AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_bedrockagent_agent" "support_agent" {
  agent_name                  = "customer-support-agent"
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  foundation_model            = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction                 = "You are a helpful customer support assistant."
  customer_encryption_key_arn = aws_kms_key.bedrock_agent.arn
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key intended for Bedrock Agent data.
2. Set `customer_encryption_key_arn` on the `aws_bedrockagent_agent` resource (or `CustomerEncryptionKeyArn` in CloudFormation) to that key's ARN.
3. Grant the Bedrock service principal (and the agent's execution role, where applicable) the necessary `kms:Decrypt`/`kms:GenerateDataKey` permissions via the key policy — Bedrock requires the key policy to explicitly allow the Bedrock service to use the key.
4. This is generally set at agent-creation time; changing the encryption key on an existing agent may not be supported in-place — check current AWS provider behavior for whether it forces a resource replacement.
5. Apply the same CMK requirement consistently across any associated Bedrock Knowledge Bases or Agent Aliases that store related data.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/BedrockAgentEncrypted.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/BedrockAgentEncrypted.py
- AWS docs: https://docs.aws.amazon.com/bedrock/latest/userguide/agents-encryption.html
