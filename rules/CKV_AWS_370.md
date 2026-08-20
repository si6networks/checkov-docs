# CKV_AWS_370: Ensure Amazon SageMaker model uses network isolation

## Severity
**MEDIUM** (score: 5.0/10)

Without network isolation, a malicious or supply-chain-compromised model/container can make outbound network calls to exfiltrate the sensitive input data it processes or attempt lateral movement within the VPC.

## Summary
This check ensures that an Amazon SageMaker Model resource has network isolation enabled, preventing the model's training/inference containers from making any outbound network calls.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::SageMaker::Model` (property `EnableNetworkIsolation`), `aws_sagemaker_model` (attribute `enable_network_isolation`)

## Why it matters
SageMaker models run arbitrary container images (often built from third-party or user-supplied code, e.g. custom inference containers, XGBoost/PyTorch/TensorFlow images with custom `inference.py` scripts). Without network isolation, these containers can make outbound network calls — to the internet or to other resources in your VPC. This is a real risk vector: a malicious or compromised container/model artifact (e.g., a poisoned pretrained model file, or a supply-chain-compromised dependency baked into the container image) could exfiltrate the input data it processes (potentially containing sensitive customer/business data), phone home to an attacker-controlled endpoint, or attempt lateral movement within your VPC. Enabling network isolation makes the container's network stack sandboxed — it can neither make outbound calls nor be reached from outside except through the SageMaker-managed inference path — closing off data-exfiltration and lateral-movement channels entirely.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) inspecting `Properties/EnableNetworkIsolation` (`enable_network_isolation`). No custom expected value is set, so the framework default of `true` is used; if the field is absent or `false`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_sagemaker_model" "fraud_model" {
  name               = "fraud-detection-model"
  execution_role_arn = aws_iam_role.sagemaker_exec.arn

  primary_container {
    image          = "123456789012.dkr.ecr.us-east-1.amazonaws.com/fraud-model:latest"
    model_data_url = "s3://models-bucket/fraud-model/model.tar.gz"
  }
}
```

## Remediated example
```hcl
resource "aws_sagemaker_model" "fraud_model" {
  name                     = "fraud-detection-model"
  execution_role_arn       = aws_iam_role.sagemaker_exec.arn
  enable_network_isolation = true

  primary_container {
    image          = "123456789012.dkr.ecr.us-east-1.amazonaws.com/fraud-model:latest"
    model_data_url = "s3://models-bucket/fraud-model/model.tar.gz"
  }
}
```

## Remediation steps
1. Set `enable_network_isolation = true` on the `aws_sagemaker_model` resource.
2. Verify your inference container doesn't require any outbound network access at runtime (e.g., calling out to a license server, downloading additional model weights at inference time, or hitting an external API) — network isolation will block these; such dependencies must be baked into the container image or pulled at build time instead.
3. This attribute is set at model-creation time; SageMaker Model resources are generally immutable — changing it requires creating a new model resource and updating the endpoint configuration/endpoint to reference it.
4. Combine with VPC configuration (`vpc_config`) on the model and appropriately restrictive security groups for defense-in-depth, even though network isolation already blocks most egress.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerModelWithNetworkIsolation.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SagemakerModelWithNetworkIsolation.py
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html
