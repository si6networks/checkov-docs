# CKV_AWS_149: Ensure that Secrets Manager secret is encrypted using KMS CMK
## Severity
**LOW** (score: 2.0/10)

Secrets Manager already encrypts secrets by default with an AWS-managed key, so this check is about upgrading to a customer-managed CMK for finer-grained key policy and rotation control over credential material, an important but incremental hardening rather than a check for wholly unencrypted secrets.

## Summary
This check verifies that a Secrets Manager secret is encrypted with a customer-managed KMS key (CMK) rather than the AWS-managed `aws/secretsmanager` key (or no key at all).

## Applicability
Terraform (`aws_secretsmanager_secret`) and CloudFormation (`AWS::SecretsManager::Secret`).

## Why it matters
Secrets Manager entries typically hold the most sensitive material in an environment — database passwords, API keys, OAuth client secrets, TLS private keys. The AWS-managed key encrypts these at rest but gives you no ability to write a custom key policy, so you cannot restrict *decrypt* access more tightly than Secrets Manager's own IAM-based access model, cannot centrally audit key usage separately from Secrets Manager API calls, and cannot revoke access to a specific secret's underlying key independent of the secret's resource policy. A customer-managed CMK lets you enforce a dedicated key policy (e.g. only specific roles/services may `kms:Decrypt`), fully control key rotation, and instantly disable the key to cut off access to the secret in an incident — none of which is possible with the shared AWS-managed key.

## How Checkov evaluates this
**Terraform**: reads `kms_key_id` from the `aws_secretsmanager_secret` config. If the attribute is absent/empty → `FAILED`. If present but its value contains the substring `"aws/"` (indicating use of the AWS-managed alias, e.g. `alias/aws/secretsmanager`) → `FAILED`. Otherwise (a customer-managed key ARN/alias/ID that doesn't contain `aws/`) → `PASSED`.

**CloudFormation**: reads `Properties.KmsKeyId`. If it is present and does **not** contain `"aws/"` → `PASSED`. Otherwise (missing, or containing `aws/`) → `FAILED`.

## Non-compliant example
```hcl
resource "aws_secretsmanager_secret" "db_password" {
  name = "prod/db/password"
  # no kms_key_id -> uses AWS-managed aws/secretsmanager key
}
```

```yaml
Resources:
  DbSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: prod/db/password
```

## Remediated example
```hcl
resource "aws_kms_key" "secrets" {
  description             = "CMK for Secrets Manager"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_secretsmanager_secret" "db_password" {
  name       = "prod/db/password"
  kms_key_id = aws_kms_key.secrets.key_id # <-- customer-managed CMK
}
```

```yaml
Resources:
  SecretsKey:
    Type: AWS::KMS::Key
    Properties:
      Description: CMK for Secrets Manager
      EnableKeyRotation: true

  DbSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: prod/db/password
      KmsKeyId: !Ref SecretsKey
```

## Remediation steps
1. Create a customer-managed KMS key dedicated to Secrets Manager (or a per-application CMK for tighter scoping).
2. Set `kms_key_id` (Terraform) or `KmsKeyId` (CloudFormation) to that key's ID/ARN — do not use the `aws/secretsmanager` alias.
3. Grant `kms:Decrypt`, `kms:GenerateDataKey`, and `kms:CreateGrant` (as needed) in the key policy to the roles/services that must read the secret.
4. Existing secrets encrypted with the AWS-managed key can be re-encrypted by updating the secret's `KmsKeyId` — Secrets Manager re-encrypts on the next `PutSecretValue`/`UpdateSecret` call.
5. Enable automatic key rotation on the CMK (`enable_key_rotation = true`) for defense-in-depth, separate from Secrets Manager's own secret-value rotation.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecretManagerSecretEncrypted.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SecretManagerSecretEncrypted.py
- AWS docs: https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html
