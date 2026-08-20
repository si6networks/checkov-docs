# CKV_AWS_117: Ensure that AWS Lambda function is configured inside a VPC

## Severity
**LOW** (score: 2.0/10)

A Lambda function running outside a VPC lacks network segmentation controls (security groups, private subnets) for reaching internal resources, widening its network exposure surface even though the function itself is still IAM-gated.

## Summary
Fails when a Lambda function is not attached to a VPC (i.e., has no `vpc_config`/`VpcConfig` set), leaving it running in AWS's default Lambda network rather than a customer-controlled VPC.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_lambda_function` resource.
- **CloudFormation/SAM**: `AWS::Lambda::Function`, `AWS::Serverless::Function`.

## Why it matters
A Lambda function deployed outside a VPC runs in an AWS-managed network with a default outbound path to the public internet, and it cannot reach resources that only have private IP addresses inside your VPC (e.g. an RDS instance in a private subnet, an internal ElastiCache cluster, or a private API endpoint) without those resources being made reachable some other way (often by loosening their network exposure). Placing the function inside a VPC lets you:
- Apply security groups and NACLs to control the function's network egress/ingress, restricting it to only the endpoints/resources it legitimately needs.
- Reach private resources (databases, internal services) without exposing them publicly.
- Route Lambda's outbound traffic through a NAT gateway/VPC endpoints for consistent logging, inspection, and IP allowlisting.

Without VPC attachment, network-layer controls over the function's traffic are effectively absent, and the function may end up requiring peer resources to be more publicly exposed than they should be, or the function is unable to reach internal-only infrastructure at all — an availability and defense-in-depth gap. Note: functions genuinely intended to run outside a VPC (pure API/webhook handlers with no private resource access needed) legitimately don't need this, so this rule is best applied selectively.

## How Checkov evaluates this
- **Terraform**: Checks whether the `vpc_config` block is present at all (`ANY_VALUE` on the `vpc_config` key). Fails if absent.
- **CloudFormation/SAM**: Checks whether `Properties/VpcConfig` is present. Fails if absent.

Note this check only verifies a `vpc_config`/`VpcConfig` block exists — it does not inspect the subnet or security group values within it.

## Non-compliant example
```hcl
resource "aws_lambda_function" "bad" {
  function_name = "internal-processor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"
  # no vpc_config block
}
```

## Remediated example
```hcl
resource "aws_lambda_function" "good" {
  function_name = "internal-processor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "function.zip"

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
}
```

## Remediation steps
1. Identify (or create) private subnets and a security group scoped to only the outbound destinations/ports the function needs (e.g. port 5432 to the RDS security group).
2. Add a `vpc_config` block specifying `subnet_ids` (typically 2+ private subnets across AZs for availability) and `security_group_ids`.
3. Ensure the Lambda execution role includes the `AWSLambdaVPCAccessExecutionRole` managed policy (or equivalent `ec2:CreateNetworkInterface`/`DescribeNetworkInterfaces`/`DeleteNetworkInterface` permissions) — required for Lambda to attach ENIs in the VPC.
4. If the function needs internet access (e.g. to call external APIs) once inside a VPC, route its subnet through a NAT gateway, since VPC-attached functions lose the default internet path.
5. Be aware attaching/detaching `vpc_config` can cause a brief function replacement/cold-start behavior change and ENI provisioning delay on first deploy; test in a non-production environment first.
6. For functions that intentionally have no need to reach private VPC resources, evaluate whether forcing VPC attachment adds unnecessary complexity/cold start latency versus the security benefit, and use a documented suppression if so.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaInVPC.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LambdaInVPC.py
- AWS documentation: https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html
