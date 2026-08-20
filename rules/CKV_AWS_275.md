# CKV_AWS_275: Disallow policies from using the AWS AdministratorAccess policy

## Severity
**HIGH** (score: 7.5/10)

A data-source lookup of AdministratorAccess is almost always a precursor to attaching that unrestricted Action:* / Resource:* policy elsewhere in the same configuration, so it flags the same full-account-takeover risk one step earlier in the pipeline.

## Summary
This check flags Terraform `data "aws_iam_policy"` data sources that reference the AWS-managed `AdministratorAccess` policy by name or ARN, discouraging its use even as a referenced/looked-up policy within configuration.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: data source `aws_iam_policy`

## Why it matters
`AdministratorAccess` grants unrestricted `Action: "*"` on `Resource: "*"` across the entire AWS account. Even when referenced only through a `data "aws_iam_policy"` lookup (rather than being attached directly), its ARN is typically retrieved specifically so it can subsequently be attached to a role, user, or group elsewhere in the same configuration — meaning a data-source reference to it is usually a precursor step to granting full administrative privileges. Flagging it at the data-source level catches this intent earlier in the configuration, before the (potentially separately-authored) attachment resource is created, and reinforces least-privilege design by making even indirect references to this policy visible to reviewers and static analysis. As with CKV_AWS_274, the underlying risk is that any principal ultimately granted this policy has full, unrestricted control of the account, making it a single point of catastrophic compromise if that principal's credentials or trust relationship is ever abused.

## How Checkov evaluates this
This check (`IAMManagedAdminPolicy`, data-source variant) inspects the `aws_iam_policy` data source's configuration:
- If a `name` attribute is present and its first value equals `"AdministratorAccess"` → **FAIL**.
- If an `arn` attribute is present and its first value equals `"arn:aws:iam::aws:policy/AdministratorAccess"` → **FAIL**.
- Otherwise → **PASS**.

Both attribute forms (`name` and `arn`) are checked independently — a data source that resolves the same policy via either lookup style triggers the same failure.

## Non-compliant example
```hcl
data "aws_iam_policy" "admin" {
  name = "AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "attach_admin" {
  role       = aws_iam_role.ci_pipeline.name
  policy_arn = data.aws_iam_policy.admin.arn
}
```

## Remediated example
```hcl
data "aws_iam_policy" "s3_read_only" {
  name = "AmazonS3ReadOnlyAccess"   # a scoped AWS-managed policy instead of AdministratorAccess
}

resource "aws_iam_role_policy_attachment" "attach_scoped" {
  role       = aws_iam_role.ci_pipeline.name
  policy_arn = data.aws_iam_policy.s3_read_only.arn
}

# Or, better still, define a custom policy scoped to only what's needed:
resource "aws_iam_policy" "ci_scoped" {
  name = "ci-pipeline-scoped-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "${aws_s3_bucket.artifacts.arn}/*"
    }]
  })
}
```

## Remediation steps
1. Find every `data "aws_iam_policy"` block that resolves `AdministratorAccess` by name or ARN.
2. Trace where that data source's `.arn` output is consumed (typically a policy attachment resource) to understand what's actually being granted broad access.
3. Replace the data-source lookup with a narrower AWS-managed policy, or better, author a custom `aws_iam_policy` scoped exactly to the required actions and resources.
4. Update the downstream attachment resource to reference the new scoped policy instead.
5. If a genuine, reviewed need for full administrative access exists (e.g., a break-glass role), isolate it to a dedicated, tightly monitored identity with MFA and session-duration limits, and suppress this check on that specific data source with a documented justification rather than leaving it as an unreviewed default.
6. This is a configuration-only change (no infrastructure replacement), but will change effective permissions for anything consuming the data source's output once applied.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/IAMManagedAdminPolicy.py
- AWS documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
