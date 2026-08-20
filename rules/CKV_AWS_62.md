# CKV_AWS_62: Ensure no IAM policies that allow full "*-*" administrative privileges are not created
## Severity
**HIGH** (score: 7.5/10)

An IAM policy granting '*' actions on '*' resources is a full administrative privilege escalation vector, letting the attached principal perform any action on any resource in the account, including creating new credentials or exfiltrating data.

## Summary
This check fails when an IAM policy document (managed or inline) contains an `Allow` statement granting `Action: "*"` on `Resource: "*"`, i.e. unrestricted administrator-equivalent permissions over every AWS action on every resource.

## Applicability
- **CloudFormation**: `AWS::IAM::Policy`, `AWS::IAM::Group`, `AWS::IAM::Role`, `AWS::IAM::User` (covers both standalone managed policies and inline `Policies` blocks embedded in group/role/user resources).
- **Terraform**: `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`.

## Why it matters
A policy statement with `"Action": "*"` and `"Resource": "*"` and `"Effect": "Allow"` is functionally equivalent to AWS's `AdministratorAccess` managed policy — it grants complete control over every service and resource in the account, including the ability to create/delete IAM users and roles, modify billing, exfiltrate data from any service, or destroy infrastructure. Attaching this to a role or user dramatically expands the blast radius of any credential compromise: a leaked access key, a compromised CI pipeline, or a compromised EC2 instance profile with this policy becomes a full account takeover rather than a contained incident. It also violates least-privilege and makes it impossible to reason about what a given identity can actually do, complicating audits and incident response. This is one of the highest-severity IAM misconfigurations Checkov detects.

## How Checkov evaluates this
Both implementations look at the policy document's `Statement` list (parsing inline policies embedded in `Properties/Policies[*]/PolicyDocument`, standalone `PolicyDocument`, or Terraform's `policy`/`inline_policy` attribute via `extract_policy_dict`):
- For each statement that has an `Action` key: read `Effect` (default `"Allow"` if omitted), `Action` (default `[""]`), `Resource` (default `[""]`).
- **FAIL** if `Effect == "Allow"` AND `"*"` is in the `Action` list AND `"*"` is in the `Resource` list.
- Otherwise **PASS** for that policy (CloudFormation iterates inline policies and returns FAILED on the first match; Terraform's exception-swallowing means any parse failure quietly PASSES).
- If there's no policy document at all, or it can't be parsed, the check returns `PASSED` or `UNKNOWN` rather than FAILED (i.e., it only flags an explicit, parseable `*`/`*`/`Allow` grant).

## Non-compliant example
```hcl
resource "aws_iam_policy" "admin_everything" {
  name = "full-admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"          # non-compliant
        Resource = "*"          # non-compliant
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_policy" "s3_read_only_for_reports" {
  name = "s3-reports-read"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::reports-bucket",
          "arn:aws:s3:::reports-bucket/*"
        ]                      # fixed: scoped actions and resources
      }
    ]
  })
}
```

## Remediation steps
1. Identify the actual set of actions and resources the role/user/policy needs, using CloudTrail access-advisor data or IAM Access Analyzer's policy generation feature to derive a least-privilege policy from observed usage.
2. Replace wildcard `Action`/`Resource` pairs with specific service actions (e.g., `s3:GetObject`) and specific ARNs (or ARN patterns scoped to a resource prefix).
3. If broad access to one service (but not all) is required, scope `Action` to that service's actions (e.g., `"s3:*"`) while still restricting `Resource`, or vice versa — the check only flags the case where *both* are `*` simultaneously.
4. For genuinely privileged break-glass roles, consider using AWS's managed `AdministratorAccess` policy (which is not itself flagged since it isn't written as an inline `"*"`/`"*"` statement in your IaC) combined with strong MFA and time-bound access via IAM Identity Center, rather than hand-rolling a wildcard inline policy.
5. No resource replacement needed; policy document updates apply in place.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMAdminPolicyDocument.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMAdminPolicyDocument.py)
- [AWS: IAM policies grant least privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
