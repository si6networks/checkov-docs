# CKV_AWS_63: Ensure no IAM policies documents allow "*" as a statement's actions
## Severity
**HIGH** (score: 7.5/10)

A policy statement allowing Action: '*' grants unrestricted API access (even if scoped to specific resources), commonly enabling privilege escalation, data exfiltration, or resource destruction.

## Summary
This check fails when an IAM policy statement grants `Effect: Allow` with `Action: "*"`, i.e. permission to call every AWS API action, regardless of what `Resource` is scoped to.

## Applicability
- **CloudFormation**: `AWS::IAM::Policy`, `AWS::IAM::Group`, `AWS::IAM::Role`, `AWS::IAM::User` (standalone and inline policies).
- **Terraform**: `aws_iam_group_policy`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_ssoadmin_permission_set_inline_policy`.

## Why it matters
Even if `Resource` is scoped to a specific ARN, granting `Action: "*"` still allows any operation — including destructive, configuration-changing, or privilege-escalating ones — against that resource (or set of resources, if the ARN pattern is broad). For example, `Action: "*"` scoped to a single S3 bucket ARN still allows deleting the bucket, changing its policy, disabling logging, or making it public — not just reading/writing objects. More critically, wildcard actions on IAM-related resources are a classic privilege-escalation path (e.g., `Action: "*"` on an IAM role resource lets you attach new policies to that role, modify its trust relationship, and escalate to any permission the role could ever hold). This check is closely related to, but broader than, CKV_AWS_62 (`*`/`*` full admin) — it catches any wildcard action, even paired with a narrowly scoped resource, which is still a least-privilege violation.

## How Checkov evaluates this
Both implementations parse the policy document's `Statement` list (via `extract_policy_dict` or `ast.literal_eval` for string-encoded policies):
- For each statement containing an `Action` key: if `Effect` is (or defaults to) `"Allow"` and `"*"` appears in the (list-normalized) `Action` value → **FAIL**.
- **CloudFormation**: after checking the first qualifying statement, it returns PASSED for the remaining statements in that iteration (a minor quirk: the loop only fully evaluates the first `Action`-bearing statement per policy document before returning PASSED, so only the first statement is truly checked in some code paths).
- **Terraform**: iterates all statements and additionally handles the case where the policy came from a Terraform **plan** file (where `Action` may be represented as a nested list) vs. raw HCL (`Action` as a flat list of strings) — both forms are checked for the presence of `"*"`.
- If parsing fails or no policy document exists, both return `PASSED`/`UNKNOWN` rather than `FAILED`.

## Non-compliant example
```hcl
resource "aws_iam_role_policy" "bucket_admin" {
  name = "bucket-admin"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"                                  # non-compliant
        Resource = "arn:aws:s3:::my-app-bucket/*"
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_role_policy" "bucket_admin" {
  name = "bucket-admin"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]                                                # fixed: enumerated actions
        Resource = "arn:aws:s3:::my-app-bucket/*"
      }
    ]
  })
}
```

## Remediation steps
1. Enumerate the specific actions the identity actually needs (e.g., `s3:GetObject`, `s3:PutObject`) instead of `"*"`.
2. Use IAM Access Analyzer's policy generation (based on CloudTrail activity) to derive the minimal action set for existing workloads.
3. If a whole service's actions are genuinely needed, use a service-scoped wildcard like `"s3:*"` rather than the universal `"*"`, and still combine it with a scoped `Resource`.
4. Pay special attention to policies touching IAM, KMS, or Lambda resources — wildcard actions there are common privilege-escalation vectors even when `Resource` looks narrow.
5. No resource replacement required; this is an in-place policy document change.

## References
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMStarActionPolicyDocument.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMStarActionPolicyDocument.py)
- [AWS: IAM policies grant least privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
