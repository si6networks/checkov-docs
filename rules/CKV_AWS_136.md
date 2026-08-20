# CKV_AWS_136: Ensure that ECR repositories are encrypted using KMS

## Severity
**LOW** (score: 2.0/10)

ECR repositories without KMS encryption still get default AES-256 encryption at rest from AWS, so the gap is the absence of customer-managed key control/rotation rather than unencrypted storage of container images.

## Summary
This check requires ECR repositories to explicitly set their encryption configuration to `KMS` rather than relying on the default `AES256` (Amazon S3-managed) encryption.

## Applicability
- **Frameworks:** Terraform (AWS provider), CloudFormation
- **Resource types:** `aws_ecr_repository` (Terraform), `AWS::ECR::Repository` (CloudFormation)

## Why it matters
ECR repositories are encrypted at rest by default using `AES256`, but this uses AWS-managed keys where the customer has no control over key policies, no ability to restrict who can decrypt image layers, and no audit trail of key usage in CloudTrail (via KMS key usage logging). Using a customer-managed KMS key instead lets you enforce fine-grained IAM/key-policy controls over who can pull/decrypt container images, revoke access by disabling the key (e.g., in response to a suspected compromise), and get a durable CloudTrail record of every decrypt operation — which matters because container images can embed application secrets, proprietary code, and infrastructure configuration. For regulated environments, KMS-based encryption is often a compliance requirement (customer-controlled key management, key rotation policy, separation of duties).

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` attribute checks:
- **Terraform:** inspects `encryption_configuration[0].encryption_type`. **PASS** only if the value equals `"KMS"`; **FAIL** if set to `"AES256"` or left unset (AES256 is the AWS default).
- **CloudFormation:** inspects `Properties.EncryptionConfiguration.EncryptionType`. Same logic — **PASS** only if `"KMS"`.

## Non-compliant example
```hcl
resource "aws_ecr_repository" "app" {
  name                 = "app-repo"
  image_tag_mutability = "IMMUTABLE"
  # encryption_configuration not set -> defaults to AES256 -> FAIL
}
```

```yaml
Resources:
  AppRepo:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: app-repo
      # EncryptionConfiguration missing -> defaults to AES256 -> FAIL
```

## Remediated example
```hcl
resource "aws_kms_key" "ecr" {
  description         = "KMS key for ECR image encryption"
  enable_key_rotation = true
}

resource "aws_ecr_repository" "app" {
  name                 = "app-repo"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"          # added
    kms_key         = aws_kms_key.ecr.arn
  }
}
```

```yaml
Resources:
  AppRepo:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: app-repo
      EncryptionConfiguration:
        EncryptionType: KMS          # added
        KmsKey: !GetAtt EcrKmsKey.Arn
```

## Remediation steps
1. Create (or reuse) a KMS key intended for ECR image encryption; enable automatic key rotation.
2. Set `encryption_configuration { encryption_type = "KMS" kms_key = <key-arn> }` (Terraform) or the equivalent `EncryptionConfiguration` block (CloudFormation).
3. **Important:** `encryption_configuration` (and its `EncryptionConfiguration` CloudFormation equivalent) can only be set at repository creation time — changing it on an existing repository requires replacing the repository (deleting and recreating it, which also deletes all stored images unless they are re-pushed/migrated first).
4. Set an appropriate KMS key policy granting the necessary IAM principals (CI/CD pipelines, EKS/ECS task execution roles) `kms:Decrypt` permission — forgetting this will break image pulls.
5. Plan a migration window: push existing images to the new KMS-encrypted repository (or a new repository) before cutting over consumers.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECRRepositoryEncrypted.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ECRRepositoryEncrypted.py)
- [AWS: Amazon ECR encryption at rest](https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html)
