# CKV_AWS_32: Ensure ECR policy is not set to public

## Severity
**MEDIUM** (score: 5.0/10)

A public ECR repository policy allows anyone on the internet to pull container images, potentially exposing proprietary application code, embedded configuration, or credentials baked into image layers.

## Summary
This check ensures ECR repository resource policies do not grant internet-accessible (effectively public/wildcard-principal) access to the repository.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** Terraform and CloudFormation
- **Resource types:** `aws_ecr_repository_policy` (Terraform); `AWS::ECR::Repository` (CloudFormation)

## Why it matters
An ECR repository whose resource policy grants access to `Principal: "*"` (unconstrained) allows anyone on the internet — not just accounts you intend — to pull (and depending on the actions permitted, potentially push) container images. For private application images this can leak proprietary source code baked into layers, embedded secrets/API keys accidentally committed to the image, internal architecture details, and dependency information useful for targeted exploitation. If push permissions are also exposed, an attacker could overwrite a tag with a malicious image that gets pulled into your deployment pipeline — a direct supply-chain compromise. This maps to identity and access management controls (NIST 800-53 AC-3, AC-6) and is one of the most common "unintentionally public" cloud storage/registry misconfigurations, analogous to a public S3 bucket.

## How Checkov evaluates this
**Terraform (`aws_ecr_repository_policy`):** Parses the `policy` attribute as an IAM-style resource policy document using the `cloudsplaining` library's `ResourcePolicyDocument`, then checks `policy.internet_accessible_actions` — **FAIL** if any actions in the policy are internet-accessible (i.e., a statement grants access to `Principal: "*"` or an equivalent wildcard without a scoping condition). **PASS** if the policy has no internet-accessible actions, or if `policy` is absent. Returns **UNKNOWN** if the policy can't be parsed as a dict.

**CloudFormation (`AWS::ECR::Repository`):** Parses `Properties.RepositoryPolicyText` and inspects each `Statement`'s `Principal`. **FAIL** if any statement has `Principal` (or `Principal.AWS`) equal to `"*"` **and** there is no scoping `Condition` using `StringEquals`/`ForAllValues:StringEquals`/`ForAnyValue:StringEquals` on `aws:PrincipalOrgID`. **PASS** otherwise, including when the policy is a Serverless Framework variable expression it can't statically resolve (logged, not failed).

## Non-compliant example
```hcl
resource "aws_ecr_repository" "example" {
  name = "example-repo"
}

resource "aws_ecr_repository_policy" "example" {
  repository = aws_ecr_repository.example.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicPull"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_ecr_repository" "example" {
  name = "example-repo"
}

resource "aws_ecr_repository_policy" "example" {
  repository = aws_ecr_repository.example.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrgAccountsPull"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = var.aws_org_id      # scopes wildcard principal to your AWS Organization
          }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Replace any `Principal: "*"` statement with an explicit list of AWS account IDs or IAM principal ARNs that legitimately need access.
2. If org-wide access truly is intended, keep the wildcard principal but add a `Condition` constraining it to `aws:PrincipalOrgID` (as shown above) or `aws:PrincipalOrgPaths` — this is what both the CloudFormation and Terraform checks explicitly treat as acceptable.
3. Prefer cross-account access via specific `arn:aws:iam::<account-id>:root` or role ARNs over any wildcard principal where possible.
4. Enable ECR image scanning and consider enabling private registry scanning to detect leaked secrets in images regardless of policy.
5. Audit existing repositories for public policies: `aws ecr get-repository-policy --repository-name <repo>`.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECRPolicy.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ECRPolicy.py
- AWS docs: https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html
