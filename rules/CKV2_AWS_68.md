# CKV2_AWS_68: Ensure SageMaker notebook instance IAM policy is not overly permissive

## Severity
**MEDIUM** (score: 5.0/10)

An IAM role attached to a SageMaker notebook with wildcard Allow:* grants the notebook's code-execution environment unrestricted control over the AWS account, effectively an admin-equivalent privilege escalation path from any code run in the notebook.

## Summary
This check ensures the IAM role attached to a SageMaker notebook instance does not grant `Allow` on `Action: "*"` (i.e., unrestricted access to every AWS API action), which would give the notebook's execution environment effectively unbounded permissions across the AWS account.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::SageMaker::NotebookInstance` + `AWS::IAM::Role` (CloudFormation); `aws_sagemaker_notebook_instance` + `aws_iam_role` (Terraform)

## Why it matters
SageMaker notebook instances run arbitrary, interactively-editable code (Jupyter notebooks) with the permissions of their attached IAM role. This is a substantially more dangerous execution context than a locked-down service role: any data scientist, contractor, or compromised credential with access to the notebook can execute arbitrary code that inherits the role's full permission set. If that role's policy grants `Action: "*"` with `Effect: Allow`, a single notebook effectively becomes an all-powerful pivot point into the AWS account — capable of reading every S3 bucket, exfiltrating secrets from Secrets Manager/SSM, creating new IAM users/roles for persistence, modifying security groups, or deleting resources account-wide. Because notebooks are often treated as "just a data science tool" and get less security scrutiny than production application roles, an overly broad policy here is a disproportionately high-value target for privilege escalation and lateral movement.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy), evaluated identically in both CloudFormation and Terraform variants:
1. Filters to `aws_sagemaker_notebook_instance` / `AWS::SageMaker::NotebookInstance` resources.
2. Requires a graph **connection** from the notebook instance to an `aws_iam_role` / `AWS::IAM::Role` (i.e., the role it assumes/uses).
3. On that connected role, inspects the policy document via JSONPath: `policy.Statement[?(@.Effect == Allow)].Action[*]` (Terraform) or `AssumeRolePolicyDocument.Statement[?(@.Effect == Allow)].Action[*]` (CloudFormation) and requires (`jsonpath_not_equals`) that none of the matched `Action` values equal `"*"`.

If any `Allow` statement on the connected role's policy grants `Action: "*"`, the check **FAILS**. Note the CloudFormation variant inspects the role's `AssumeRolePolicyDocument` (trust policy) specifically, while the Terraform variant inspects the role's attached `policy` — reflecting differences in how each framework's graph typically wires the relevant IAM document.

## Non-compliant example
```hcl
resource "aws_iam_role" "notebook_role" {
  name = "sagemaker-notebook-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sagemaker.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  # Attached inline policy grants unrestricted access -> FAILS
  inline_policy {
    name = "overly-permissive"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }]
    })
  }
}

resource "aws_sagemaker_notebook_instance" "analysis" {
  name          = "data-analysis"
  role_arn      = aws_iam_role.notebook_role.arn
  instance_type = "ml.t3.medium"
}
```

## Remediated example
```hcl
resource "aws_iam_role" "notebook_role" {
  name = "sagemaker-notebook-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sagemaker.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  inline_policy {
    name = "scoped-access"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::acme-ml-datasets/*"
      }]
    })
  }
}

resource "aws_sagemaker_notebook_instance" "analysis" {
  name          = "data-analysis"
  role_arn      = aws_iam_role.notebook_role.arn
  instance_type = "ml.t3.medium"
}
```

## Remediation steps
1. Identify every IAM role attached to SageMaker notebook instances (`role_arn` on the Terraform resource, `RoleArn` in CloudFormation) and audit their attached/inline policies.
2. Replace any `Action: "*"` grant with an explicit, minimal list of actions the notebook's workload actually needs (e.g., specific S3, SageMaker, CloudWatch Logs actions).
3. Scope `Resource` as narrowly as possible in the same statements (e.g., specific bucket ARNs) rather than `"*"`, even though this specific check only flags the `Action` wildcard.
4. Use IAM Access Analyzer or CloudTrail-based least-privilege generation to derive the actual permission set in use before tightening a long-lived overly broad role.
5. Retest notebook workflows after tightening the policy — this is a behavioral change (not just metadata) and can break jobs relying on undocumented broad access.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/SageMakerIAMPolicyOverlyPermissiveToAllTraffic.json
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/graph_checks/SageMakerIAMPolicyOverlyPermissiveToAllTraffic.json
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html
