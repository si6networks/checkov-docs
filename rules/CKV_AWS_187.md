# CKV_AWS_187: Ensure Sagemaker domain and notebook instance are encrypted by KMS using a customer managed Key (CMK)
## Severity
**LOW** (score: 2.0/10)

SageMaker domains/notebooks often handle training data and credentials that can be sensitive, and while this check only enforces CMK usage over default AWS-managed encryption, losing that key-level control is a moderate exposure for an ML environment.

## Summary
This check requires that SageMaker Domains and Notebook Instances specify a customer-managed KMS key for encrypting their attached storage, instead of relying on the AWS-managed default key.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Resource/entity types:** `AWS::SageMaker::NotebookInstance`, `AWS::SageMaker::Domain` (CloudFormation); `aws_sagemaker_domain`, `aws_sagemaker_notebook_instance` (Terraform)
- **Check type:** resource (attribute-value check), separate implementations per framework/resource

## Why it matters
SageMaker notebook instances and domains are used by data scientists to explore data, train models, and often store credentials, dataset samples, and proprietary model code directly on the attached EBS volume / EFS storage. Without a customer-managed KMS key, this storage defaults to AWS-managed encryption, meaning your organization cannot enforce a fine-grained key policy restricting which specific data scientists, service roles, or automation pipelines can decrypt the notebook's persistent storage. Given that notebooks frequently contain hard-coded API keys, unmasked training data samples (which may include PII), or unpublished model artifacts, using a CMK is critical to maintaining an auditable, revocable access control boundary around this data — you can disable the key to instantly cut off access org-wide if a notebook is compromised or an employee is offboarded, which is not possible with the default key.

## How Checkov evaluates this
Two separate implementations, both `BaseResourceValueCheck` subclasses expecting `ANY_VALUE`:
- **CloudFormation:** inspects `Properties/KmsKeyId` on `AWS::SageMaker::NotebookInstance` and `AWS::SageMaker::Domain`. Presence of any value passes; absence fails.
- **Terraform:** inspects the `kms_key_id` attribute on `aws_sagemaker_domain` and `aws_sagemaker_notebook_instance`. Same pass/fail logic.

## Non-compliant example
```hcl
resource "aws_sagemaker_notebook_instance" "example" {
  name          = "data-science-notebook"
  role_arn      = aws_iam_role.sagemaker.arn
  instance_type = "ml.t3.medium"
  # kms_key_id not set -- uses AWS-managed default key
}
```

```yaml
Resources:
  NotebookInstance:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      InstanceType: ml.t3.medium
      RoleArn: !GetAtt SageMakerRole.Arn
      # KmsKeyId not set
```

## Remediated example
```hcl
resource "aws_kms_key" "sagemaker" {
  description             = "CMK for SageMaker storage encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_sagemaker_notebook_instance" "example" {
  name          = "data-science-notebook"
  role_arn      = aws_iam_role.sagemaker.arn
  instance_type = "ml.t3.medium"
  kms_key_id    = aws_kms_key.sagemaker.arn  # customer managed key
}
```

```yaml
Resources:
  NotebookInstance:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      InstanceType: ml.t3.medium
      RoleArn: !GetAtt SageMakerRole.Arn
      KmsKeyId: !Ref SageMakerKmsKey
```

## Remediation steps
1. Create or select a customer-managed KMS key with a key policy restricted to the data science team's roles and the SageMaker execution role.
2. Set `kms_key_id` (Terraform) / `KmsKeyId` (CloudFormation) on the SageMaker Domain and/or Notebook Instance resource.
3. Grant the SageMaker execution role `kms:CreateGrant`, `kms:Decrypt`, and `kms:DescribeKey` on the CMK.
4. Note: for existing notebook instances, the KMS key is generally fixed at creation and changing it may require stopping/recreating the instance; for SageMaker Domains, verify current provider support for in-place updates before assuming zero downtime.
5. Apply the same CMK strategy to any associated EFS storage used by SageMaker Studio domains, since domain-level encryption covers the shared EFS volume.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SagemakerNotebookEncryptedWithCMK.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerDomainEncryptedWithCMK.py)
- [AWS SageMaker encryption at rest documentation](https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html)
