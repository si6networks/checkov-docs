# CKV_AWS_274: Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy

## Severity
**HIGH** (score: 7.5/10)

Attaching AdministratorAccess grants unrestricted Action:* / Resource:* across the entire account, so any compromise of the role, user, or group it's attached to is equivalent to full account takeover.

## Summary
This check flags IAM roles and policy-attachment resources that attach the AWS-managed `AdministratorAccess` policy, which grants unrestricted (`*:*`) permissions across the entire AWS account.

## Applicability
- **Terraform**: resources `aws_iam_role` (via inline `managed_policy_arns`), `aws_iam_policy_attachment`, `aws_iam_role_policy_attachment`, `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, `aws_ssoadmin_managed_policy_attachment`

## Why it matters
`AdministratorAccess` (`arn:aws:iam::aws:policy/AdministratorAccess`) grants `Action: "*"` on `Resource: "*"` — full control over every service and resource in the account, including the ability to modify IAM itself, delete CloudTrail logs, exfiltrate data from any service, and re-provision or destroy infrastructure. Attaching this policy to a role, user, or group violates the principle of least privilege at the most extreme level: a single compromised credential, a misused CI/CD role, or an over-broadly scoped service integration with this policy attached becomes a full account takeover vector. Best practice is to grant only the specific permissions a role/user/group actually needs, using scoped custom policies or narrower AWS-managed policies, and to reserve genuinely administrative access for a small number of tightly monitored, MFA-protected break-glass identities — not for routine roles or automation.

## How Checkov evaluates this
This check (`IAMManagedAdminPolicy`) branches on the resource type:
- **`aws_iam_role`**: if `managed_policy_arns` is present and the `AdministratorAccess` ARN (`arn:aws:iam::aws:policy/AdministratorAccess`) appears in the first element → **FAIL**.
- **`aws_iam_policy_attachment` / `aws_iam_role_policy_attachment` / `aws_iam_user_policy_attachment` / `aws_iam_group_policy_attachment`**: if `policy_arn` equals the AdministratorAccess ARN → **FAIL**.
- **`aws_ssoadmin_managed_policy_attachment`**: if `managed_policy_arn` equals the AdministratorAccess ARN → **FAIL**.
- In all other cases (no match, or a different policy referenced) → **PASS**.

Only the exact `AdministratorAccess` managed policy ARN triggers this check; custom policies with broad permissions (even `Action: "*"`) written as inline/custom policy documents are not caught by this specific check.

## Non-compliant example
```hcl
resource "aws_iam_role" "ci_pipeline" {
  name = "ci-pipeline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}
```

## Remediated example
```hcl
resource "aws_iam_role" "ci_pipeline" {
  name = "ci-pipeline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  managed_policy_arns = [aws_iam_policy.ci_scoped.arn]
}

resource "aws_iam_policy" "ci_scoped" {
  name = "ci-pipeline-scoped-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.artifacts.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:PutImage"]
        Resource = "*"
      }
    ]
  })
}
```

## Remediation steps
1. Identify what the role/user/group with `AdministratorAccess` actually needs to do — enumerate the specific API actions and resources it touches.
2. Write a scoped custom IAM policy (or use a narrower AWS-managed policy, e.g. `AmazonS3FullAccess` only if genuinely needed) that grants only those permissions.
3. Replace the `AdministratorAccess` reference in `managed_policy_arns` / `policy_arn` / `managed_policy_arn` with the new scoped policy's ARN.
4. Test thoroughly in a non-production environment — overly narrow policies will cause `AccessDenied` errors that need to be iteratively addressed by adding the missing specific actions (consider AWS IAM Access Analyzer's policy generation from CloudTrail activity to help scope this).
5. If truly privileged/break-glass access is required for a small set of human operators, use a separate, tightly audited role with MFA-required assumption and short session durations, rather than attaching this policy broadly or to automation.
6. This is a policy-attachment change, not a resource replacement — applying it does not require recreating the role/user/group, but will change effective permissions immediately.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMManagedAdminPolicy.py
- AWS documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
