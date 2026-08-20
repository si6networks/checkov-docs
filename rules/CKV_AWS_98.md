# CKV_AWS_98: Ensure all data stored in the Sagemaker Endpoint is securely encrypted at rest

## Severity
**HIGH** (score: 7.5/10)

Unencrypted storage for a SageMaker endpoint configuration leaves model artifacts and inference data at rest unprotected, risking exposure of proprietary models or sensitive input/output data.

## Summary
This check fails when an AWS SageMaker endpoint configuration does not specify a `kms_key_arn`, meaning the storage volumes attached to the endpoint's instances are not encrypted with a customer-managed (or any explicit) KMS key.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_sagemaker_endpoint_configuration` resource — inspects the `kms_key_arn` attribute.

## Why it matters
A SageMaker endpoint hosts a deployed ML model along with the storage volume attached to its serving instances, which can hold model artifacts, cached inference data, and potentially sensitive input/output payloads depending on the workload (e.g., PII processed by an NLP model, medical images for a diagnostic model). Without at-rest encryption via a KMS key, that storage volume is either unencrypted or relies on AWS-managed defaults with no organizational control over key policy, rotation, or access auditing. Specifying a customer-managed KMS key ensures the data is cryptographically protected and gives the organization the ability to control who can decrypt it (via key policy), audit key usage (via CloudTrail), and revoke access (by disabling/rotating the key) independent of IAM permissions on the SageMaker resource itself.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using the `ANY_VALUE` sentinel: it inspects the `kms_key_arn` attribute and passes as long as any non-empty value is set there — it does not validate the ARN format or that the referenced key exists/is valid, only that the field is populated. If `kms_key_arn` is absent → FAILED.

## Non-compliant example
```hcl
resource "aws_sagemaker_endpoint_configuration" "model" {
  name = "my-model-endpoint-config"

  production_variants {
    variant_name           = "primary"
    model_name              = aws_sagemaker_model.model.name
    instance_type            = "ml.t2.medium"
    initial_instance_count = 1
  }
  # no kms_key_arn set
}
```

## Remediated example
```hcl
resource "aws_kms_key" "sagemaker" {
  description = "KMS key for SageMaker endpoint storage encryption"
}

resource "aws_sagemaker_endpoint_configuration" "model" {
  name         = "my-model-endpoint-config"
  kms_key_arn = aws_kms_key.sagemaker.arn

  production_variants {
    variant_name           = "primary"
    model_name              = aws_sagemaker_model.model.name
    instance_type            = "ml.t2.medium"
    initial_instance_count = 1
  }
}
```

## Remediation steps
1. Create or designate a customer-managed KMS key for SageMaker endpoint storage.
2. Set `kms_key_arn` on the `aws_sagemaker_endpoint_configuration` resource to that key's ARN.
3. Grant the SageMaker execution role permission to use the key (`kms:CreateGrant`, `kms:Decrypt`, `kms:DescribeKey`, `kms:GenerateDataKey`) via the key policy.
4. Note: some SageMaker instance types (e.g., certain ml.* families that only support instance store volumes) may not support KMS-based encryption of local storage — check the specific instance type's storage documentation if this attribute doesn't apply.
5. Updating `kms_key_arn` on an existing endpoint configuration requires creating a new endpoint configuration and updating the endpoint to use it, since endpoint configurations are immutable once created.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerEndpointConfigurationEncryption.py
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html
