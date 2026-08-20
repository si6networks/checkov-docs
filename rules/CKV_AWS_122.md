# CKV_AWS_122: Ensure that direct internet access is disabled for an Amazon SageMaker Notebook Instance

## Severity
**LOW** (score: 2.0/10)

A SageMaker notebook instance with direct internet access removes network isolation from a code-execution environment that typically holds IAM credentials and access to training data, increasing the risk of data exfiltration or lateral movement if the instance is compromised.

## Summary
Fails when an `aws_sagemaker_notebook_instance` allows direct internet access instead of routing all traffic through a customer-managed VPC.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_sagemaker_notebook_instance` resource.

## Why it matters
SageMaker Notebook Instances are fully managed Jupyter notebook environments frequently used to access sensitive training data, model artifacts, and credentials (often via attached IAM roles with broad data-access permissions to S3 buckets, databases, etc.). When `direct_internet_access` is enabled (the default), the notebook instance has an unrestricted network path to the public internet through an AWS-managed ENI, bypassing any customer VPC-level security controls (security groups, NACLs, VPC endpoint policies, egress filtering/proxies). This creates two risks:
- **Data exfiltration**: A compromised notebook (e.g. via a malicious dependency installed in the Python/conda environment, or a supply-chain-compromised notebook extension) can exfiltrate sensitive training data or model artifacts directly to attacker-controlled internet endpoints, with no network-layer control to detect or block it.
- **Unrestricted external code fetch**: Notebooks can `pip install`/`curl` arbitrary code from the internet without going through any organizational security gateway, increasing the risk of installing malicious or vulnerable packages that then have full access to whatever the notebook's IAM role can reach.

Disabling direct internet access forces all traffic through the customer's VPC, where NAT gateways, security groups, and (optionally) network firewalls/proxies can enforce egress allowlisting and traffic inspection.

## How Checkov evaluates this
Checks the `direct_internet_access` attribute:
- **PASS** if the `direct_internet_access` block/attribute is absent entirely (the check uses `missing_block_result=CheckResult.PASSED` — an odd default, but reflects that when this attribute is unset alongside a `subnet_id`, SageMaker's actual default behavior varies; Checkov treats "unset" leniently).
- **PASS** if `direct_internet_access = "Disabled"`.
- **FAIL** if `direct_internet_access = "Enabled"` (or set to any value other than `"Disabled"`).

## Non-compliant example
```hcl
resource "aws_sagemaker_notebook_instance" "bad" {
  name                    = "training-notebook"
  role_arn                = aws_iam_role.sagemaker.arn
  instance_type           = "ml.t3.medium"
  subnet_id               = aws_subnet.private.id
  security_groups         = [aws_security_group.notebook.id]
  direct_internet_access  = "Enabled"
}
```

## Remediated example
```hcl
resource "aws_sagemaker_notebook_instance" "good" {
  name                    = "training-notebook"
  role_arn                = aws_iam_role.sagemaker.arn
  instance_type           = "ml.t3.medium"
  subnet_id               = aws_subnet.private.id
  security_groups         = [aws_security_group.notebook.id]
  direct_internet_access  = "Disabled"
}
```

## Remediation steps
1. Set `direct_internet_access = "Disabled"` on the notebook instance.
2. Ensure the notebook's `subnet_id` is a private subnet with a route to a NAT gateway (or VPC endpoints for AWS services it needs, e.g. S3, SageMaker API/runtime, ECR) — disabling direct internet access without a NAT path will break the notebook's ability to reach package repositories (PyPI, conda) or AWS APIs.
3. Use VPC endpoints (Gateway endpoint for S3, Interface endpoints for SageMaker API/Runtime, STS, CloudWatch Logs, ECR) to avoid routing AWS API traffic through the public internet even via NAT.
4. Configure the associated security group to allow only the specific egress needed (e.g. HTTPS to your package mirror or approved endpoints) rather than unrestricted outbound.
5. This is a create-time setting for the notebook instance and typically requires recreating the instance if changed after the fact — plan for the resource replacement and any saved-notebook-content backup accordingly.
6. If your workflow requires internet access for package installation, consider a private PyPI/conda mirror reachable only via the VPC, rather than re-enabling direct internet access.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SageMakerInternetAccessDisabled.py
- AWS documentation: https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html
