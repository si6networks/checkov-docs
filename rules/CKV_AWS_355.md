# CKV_AWS_355: Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
## Severity
**HIGH** (score: 7.5/10)

An IAM policy that grants restrictable, privilege-sensitive actions against a wildcard ("*") resource removes any resource-level boundary on those permissions, letting the granted identity act against any resource in the account, a hallmark of overly permissive IAM that enables privilege escalation and lateral movement.

## Summary
Flags IAM policy resources whose policy document grants "restrictable" (i.e., resource-scopable) IAM actions against a wildcard `"*"` resource, using the `cloudsplaining` library's privilege-escalation/over-permissioning analysis.

## Applicability
- **Framework**: Terraform
- **Resource types**: `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`
- **Type**: resource check (evaluates the policy document embedded/attached directly in these resources)

## Why it matters
Many IAM actions support (and per AWS best practice, should have) resource-level permissions — for example, `s3:GetObject` can and should be scoped to specific bucket ARNs, `secretsmanager:GetSecretValue` to specific secret ARNs, `kms:Decrypt` to specific key ARNs. When a policy grants such "restrictable" actions with `"Resource": "*"` instead of a scoped ARN, the granted principal (user, role, or SSO permission set) can act on *every* resource of that type in the account, not just the ones it actually needs. This directly enlarges the blast radius of a compromised credential or an over-trusted service — e.g., a Lambda role meant to read one specific S3 bucket for its function could instead read every bucket in the account if `s3:GetObject` is granted with `Resource: "*"`. It also frequently signals broader over-permissioning that facilitates privilege escalation paths (a core finding category the `cloudsplaining` engine specializes in), since wildcard-resource policies are often combined with wildcard actions or attached to many principals.

## How Checkov evaluates this
Rather than custom Checkov logic, this check delegates to the open-source `cloudsplaining` library via `BaseTerraformCloudsplainingResourceIAMCheck`. Checkov extracts the policy JSON from the resource's `policy` attribute, builds a `cloudsplaining.scan.policy_document.PolicyDocument` object from it, and calls `policy.all_allowed_unrestricted_actions`. This cloudsplaining property inspects each statement in the policy: for actions in AWS's catalog of actions that support resource-level permissions, if the statement's `Resource` is `"*"` (and there's no scoping condition that meaningfully narrows it), those actions are added to the "unrestricted actions" list.
- **FAIL**: `all_allowed_unrestricted_actions` returns a non-empty list (one or more restrictable actions granted against `"*"`).
- **PASS**: the list is empty — every restrictable action in the policy is scoped to specific resource ARNs.

Note: actions that don't support resource-level permissions in AWS at all (e.g., some list/describe-type actions) are not flagged by this logic even with `Resource: "*"`, since there's no way to scope them regardless.

## Non-compliant example
```hcl
resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "lambda-s3-access"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "*"   # grants access to every bucket in the account
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "lambda-s3-access"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.function_data.arn}/*"   # scoped to the specific bucket
      }
    ]
  })
}
```

## Remediation steps
1. Run `cloudsplaining` or review Checkov's finding to identify exactly which actions in the policy were flagged as unrestricted.
2. For each flagged action, replace `Resource: "*"` with the specific ARN(s) (or ARN pattern with wildcards limited to a resource name/prefix, e.g. `arn:aws:s3:::my-bucket/*`) that the principal actually needs.
3. Where the resource ARN isn't known statically (e.g., dynamically created resources), use Terraform interpolation to reference the actual resource's `.arn` attribute rather than hardcoding or wildcarding.
4. If truly account-wide access is required for an action (rare, and usually a design smell), document the justification explicitly and consider whether a permissions boundary or SCP can offset the risk.
5. Re-scan with Checkov/cloudsplaining after the change to confirm `all_allowed_unrestricted_actions` is empty for the policy.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMStarResourcePolicyDocument.py
- cloudsplaining project: https://github.com/salesforce/cloudsplaining
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
