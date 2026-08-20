# CKV_AWS_60: Ensure IAM role allows only specific services or principals to assume it
## Severity
**HIGH** (score: 7.5/10)

An IAM role trust policy that fails to restrict which principals or services can assume it can allow unintended or overly broad entities to obtain the role's permissions, enabling privilege escalation.

## Summary
This check fails when an IAM role's trust policy (`AssumeRolePolicyDocument`) contains an `Allow` statement whose `Principal.AWS` is the wildcard `"*"`, meaning literally any AWS account or entity (given the right conditions/credentials) could assume the role.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::IAM::Role`, property `Properties/AssumeRolePolicyDocument`.
- **Terraform**: `aws_iam_role` resource, attribute `assume_role_policy`.

## Why it matters
A role's trust policy is the gatekeeper that decides who can call `sts:AssumeRole` to obtain temporary credentials for that role. Setting `Principal: { "AWS": "*" }` (with `Effect: Allow`) removes that gate entirely for the AWS-principal dimension — any AWS account, including ones outside your organization, could potentially assume the role if they also satisfy any other loosely-configured conditions (or if there are no conditions at all). This is a critical privilege-escalation and cross-account-takeover vector: attackers routinely scan for exactly this misconfiguration to pivot into victim AWS accounts, especially when the role also carries powerful permissions (e.g., `AdministratorAccess`). The check correctly skips statements with `Effect: Deny`, since an explicit deny of `*` is a legitimate (if unusual) pattern and does not grant access.

## How Checkov evaluates this
Both implementations walk `AssumeRolePolicyDocument.Statement` (parsing it from JSON if it's a string):
- For each statement, if `Effect == "Deny"`, skip it (does not cause failure).
- Otherwise, inspect `Principal.AWS`. If it's the literal string `"*"`, or a list containing `"*"`, → **FAIL**.
- If no statement matches this pattern, → **PASS**.
- If the trust policy is absent, malformed, or unparsable, both handle this by returning `PASSED` (CloudFormation, if no `AssumeRolePolicyDocument`) or, in Terraform, silently passing through the exception handler (any parsing failure also results in PASSED).

Note this check specifically targets `Principal.AWS: "*"` (any AWS account/user); it does not flag `Principal.Service` wildcards (i.e., allowing an AWS service like `ec2.amazonaws.com` is fine and expected) or Federated/other principal types.

## Non-compliant example
```hcl
resource "aws_iam_role" "cross_account" {
  name = "shared-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }   # non-compliant: anyone can assume
        Action    = "sts:AssumeRole"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_role" "cross_account" {
  name = "shared-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::111122223333:root" }  # fixed: specific account
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "sts:ExternalId" = "unique-shared-secret" }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Replace `Principal.AWS: "*"` with the specific AWS account ARN(s), IAM user/role ARN(s), or use `Principal.Service` if the intended assumer is an AWS service.
2. For legitimate cross-account access, scope to the specific external account's ARN and add an `sts:ExternalId` condition to prevent the "confused deputy" problem.
3. If broad access is genuinely required (e.g., a support/break-glass role), add strict `Condition` blocks (e.g., `aws:PrincipalOrgID`, MFA requirements) rather than leaving `Principal` unrestricted — note this check does not inspect `Condition` blocks, so a wildcard principal with conditions still fails this check; consider whether the condition is sufficient compensating control and suppress with a documented justification if so.
4. Audit any existing roles with wildcard trust policies for signs of prior unauthorized assumption via CloudTrail (`AssumeRole` events from unexpected account IDs).
5. No resource replacement required — trust policy updates are in-place.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMRoleAllowsPublicAssume.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMRoleAllowsPublicAssume.py)
- [AWS: IAM roles terms and concepts](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html)
