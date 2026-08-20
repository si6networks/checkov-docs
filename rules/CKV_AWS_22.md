# CKV_AWS_22: Ensure SageMaker Notebook is encrypted at rest using KMS CMK
## Severity
**LOW** (score: 2.0/10)

A SageMaker notebook instance without a customer-managed KMS key relies on weaker key-management controls for storage that can contain training data, credentials, or proprietary models.

## Summary
This check ensures that an Amazon SageMaker notebook instance (`aws_sagemaker_notebook_instance`) specifies a customer-managed KMS key (CMK) to encrypt its attached storage volume at rest.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_sagemaker_notebook_instance`

## Why it matters
SageMaker notebook instances are interactive Jupyter environments used by data scientists to explore datasets, prototype ML models, and often store credentials (AWS access keys, database connection strings, API tokens) and training data directly on the instance's local EBS volume. Without a customer-managed key, the volume's storage is encrypted (if at all) using AWS-managed keys that your organization cannot control the policy, rotation, or audit trail for. Since notebook instances frequently hold copies of production or sensitive training data (which may include PII or proprietary business data used for model training) as well as embedded secrets used to reach data sources, a CMK gives you the ability to enforce least-privilege key policies restricting who can decrypt the volume, get detailed CloudTrail logging of every key usage, and revoke access immediately (by disabling the key) if the notebook instance or an associated IAM role is compromised.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `kms_key_id` attribute:
- The expected value is `ANY_VALUE`, meaning any non-empty value satisfies the check.
- If `kms_key_id` is set to any value, the check **PASSES**.
- If `kms_key_id` is absent, the check **FAILS** (default missing-block behavior).

## Non-compliant example
```hcl
resource "aws_sagemaker_notebook_instance" "example" {
  name          = "example-notebook"
  role_arn      = aws_iam_role.sagemaker.arn
  instance_type = "ml.t2.medium"
}
```

## Remediated example
```hcl
resource "aws_kms_key" "notebook_cmk" {
  description             = "CMK for SageMaker notebook volume encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_sagemaker_notebook_instance" "example" {
  name          = "example-notebook"
  role_arn      = aws_iam_role.sagemaker.arn
  instance_type = "ml.t2.medium"
  kms_key_id    = aws_kms_key.notebook_cmk.arn
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key with a key policy that restricts usage to the SageMaker execution role and other legitimate administrative principals.
2. Set `kms_key_id` on the `aws_sagemaker_notebook_instance` resource to that key's ARN.
3. Note: `kms_key_id` can only be set at creation time in most SageMaker API versions — changing it on an existing unencrypted (or differently-keyed) notebook instance requires replacing the resource, which will destroy the existing notebook's local storage; back up any needed notebooks/data first.
4. Ensure the SageMaker execution role has `kms:Decrypt` and `kms:GenerateDataKey` permissions on the CMK.
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerNotebookEncryption.py)
- [AWS SageMaker: Protect Data at Rest Using Encryption](https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html)
