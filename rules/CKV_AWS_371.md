# CKV_AWS_371: Ensure Amazon SageMaker Notebook Instance only allows for IMDSv2

## Severity
**MEDIUM** (score: 5.0/10)

Allowing IMDSv1 permits any code that can coerce a single unauthenticated GET request from the instance (e.g. via SSRF in a notebook dependency) to retrieve the instance's IAM role credentials outright, the exact mechanism behind the 2019 Capital One breach.

## Summary
This check ensures that a SageMaker Notebook Instance's Instance Metadata Service configuration requires version 2 (IMDSv2), preventing use of the older, more vulnerable IMDSv1.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::SageMaker::NotebookInstance` (property `InstanceMetadataServiceConfiguration/MinimumInstanceMetadataServiceVersion`), `aws_sagemaker_notebook_instance` (attribute `instance_metadata_service_configuration[0].minimum_instance_metadata_service_version`)

## Why it matters
The EC2/SageMaker Instance Metadata Service (IMDS) exposes the instance's IAM role credentials and other metadata via a well-known link-local address (`169.254.169.254`). IMDSv1 answers plain, unauthenticated GET requests to this endpoint — meaning any code able to make an HTTP request from the instance (including via a Server-Side Request Forgery, SSRF, vulnerability in a notebook's installed packages, a malicious Jupyter kernel extension, or a compromised dependency) can retrieve the instance's temporary IAM credentials with a single unauthenticated GET request. This exact pattern was the mechanism behind the 2019 Capital One breach, where an SSRF vulnerability was used to retrieve IAM credentials via IMDSv1 and exfiltrate data from S3. IMDSv2 requires a session-oriented, token-based PUT request first (with a hop-limit-constrained token), which meaningfully blocks naive SSRF exploitation since most SSRF primitives can only coerce GET requests or can't forward custom headers/PUT verbs. Notebook instances are especially exposed to this risk because they run arbitrary user/data-science code and frequently pull untrusted packages and notebooks.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) expecting `InstanceMetadataServiceConfiguration/MinimumInstanceMetadataServiceVersion` (`instance_metadata_service_configuration[0].minimum_instance_metadata_service_version`) to equal the string `"2"`. If the field is absent (IMDSv1 remains allowed by default) or set to `"1"`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_sagemaker_notebook_instance" "data_science" {
  name          = "data-science-notebook"
  role_arn      = aws_iam_role.sagemaker_notebook.arn
  instance_type = "ml.t3.medium"
  # No instance_metadata_service_configuration -> IMDSv1 remains usable
}
```

## Remediated example
```hcl
resource "aws_sagemaker_notebook_instance" "data_science" {
  name          = "data-science-notebook"
  role_arn      = aws_iam_role.sagemaker_notebook.arn
  instance_type = "ml.t3.medium"

  instance_metadata_service_configuration {
    minimum_instance_metadata_service_version = "2"
  }
}
```

## Remediated (CloudFormation) example
```yaml
Resources:
  DataScienceNotebook:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      NotebookInstanceName: data-science-notebook
      RoleArn: !GetAtt SageMakerNotebookRole.Arn
      InstanceType: ml.t3.medium
      InstanceMetadataServiceConfiguration:
        MinimumInstanceMetadataServiceVersion: "2"
```

## Remediation steps
1. Add the `instance_metadata_service_configuration` block with `minimum_instance_metadata_service_version = "2"`.
2. Confirm any custom notebook lifecycle-configuration scripts, installed SDKs, or older AWS SDK versions used within notebooks support IMDSv2 (older SDK versions or custom scripts making raw metadata requests without the token exchange will break).
3. This setting typically requires stopping and restarting (or recreating) the notebook instance to take effect — plan for a maintenance window.
4. Consider setting `HttpTokens = required` equivalents organization-wide (EC2 instances, ECS task metadata) as this is a broader hardening pattern, not SageMaker-specific.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerNotebookInstanceAllowsIMDSv2.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SagemakerNotebookInstanceAllowsIMDSv2.py
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-instance-metadata-service.html
- AWS IMDSv2 background: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
