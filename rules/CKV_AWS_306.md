# CKV_AWS_306: Ensure SageMaker notebook instances should be launched into a custom VPC
## Severity
**HIGH** (score: 7.0/10)

This check verifies SageMaker notebook instances are launched into a custom VPC rather than default networking; running outside a controlled VPC removes the ability to enforce network segmentation and security-group restrictions around a service that has broad access to training data and IAM credentials.

## Summary
This check ensures an `aws_sagemaker_notebook_instance` resource sets a `subnet_id`, placing it inside a customer-defined VPC subnet rather than in the AWS-managed default network.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_sagemaker_notebook_instance`

## Why it matters
By default, a SageMaker notebook instance is provisioned with direct internet access on an AWS-managed network that is not subject to your organization's VPC-level network controls (security groups, NACLs, VPC flow logs, private connectivity to internal data sources, or centralized egress/DLP inspection). This means data scientists' notebooks — which often have broad IAM permissions to read training data, model artifacts, and sometimes production data sources — can communicate with the internet or other AWS resources without passing through your organization's network security boundary. Launching the instance into a custom VPC lets you apply security groups to restrict inbound/outbound traffic, route traffic through a NAT gateway or VPC endpoints for private access to S3/other AWS services (avoiding public internet egress of training data), and capture VPC Flow Logs for network-level audit and anomaly detection. This maps to the NIST 800-53 boundary protection and access control family (AC-3, AC-4, AC-6, SC-7) cited in the check's own docstring.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check) using `ANY_VALUE` as the expected value. It inspects the `subnet_id` attribute:
- **PASS** if `subnet_id` is set to any non-empty value.
- **FAIL** if `subnet_id` is missing or empty (instance launches into the AWS-managed default network).

## Non-compliant example
```hcl
resource "aws_sagemaker_notebook_instance" "example" {
  name          = "data-science-notebook"
  role_arn      = aws_iam_role.sagemaker.arn
  instance_type = "ml.t3.medium"
  # subnet_id not set -> launches into default AWS-managed network, check FAILS
}
```

## Remediated example
```hcl
resource "aws_sagemaker_notebook_instance" "example" {
  name           = "data-science-notebook"
  role_arn       = aws_iam_role.sagemaker.arn
  instance_type  = "ml.t3.medium"
  subnet_id      = aws_subnet.sagemaker_private.id       # custom VPC subnet
  security_groups = [aws_security_group.sagemaker.id]     # scoped network access
}
```

## Remediation steps
1. Create (or reuse) a private subnet in your organization's VPC dedicated to SageMaker workloads, with appropriate route tables (NAT gateway or VPC endpoints for AWS service access, no direct 0.0.0.0/0 route if fully private is desired).
2. Set `subnet_id` on the `aws_sagemaker_notebook_instance` resource to that subnet's ID, and attach a restrictive `security_groups` list.
3. If the notebook needs to reach S3, ECR, or other AWS services without traversing the public internet, provision VPC Gateway/Interface Endpoints for those services.
4. Note: SageMaker notebook instances launched without a VPC cannot be modified in-place to add one — you must recreate the notebook instance (this causes a brief interruption; back up any local notebook files first, or better, keep notebooks in a Git-backed repository).
5. Enable VPC Flow Logs on the subnet for network-level audit visibility.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerNotebookInCustomVPC.py)
