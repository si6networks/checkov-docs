# CKV_AWS_49: Ensure no IAM policies documents allow "*" as a statement's actions
## Severity
**HIGH** (score: 7.5/10)

An IAM policy statement that allows "*" as its actions grants effectively unrestricted, wildcard administrative permissions to whatever principal the policy is attached to, matching the highest-impact IAM misconfiguration class.

## Summary
This check flags IAM policy documents that contain an `Allow` statement granting the wildcard action `"*"`, which grants unrestricted permissions across every AWS action the attached principal can reach.

## Applicability
- **Frameworks:** Terraform, Serverless Framework
- **Resource/entity types:**
  - Terraform: `aws_iam_policy_document` (data source), inspecting `statement` blocks
  - Serverless: `serverless_aws` function IAM role statements (`iamRoleStatements` in `provider.aws`)

## Why it matters
An IAM statement with `Action: "*"` and `Effect: Allow` grants every action across every AWS service the resource scope (`Resource`) permits — not just the specific operations the workload actually needs. Combined with an overly broad `Resource: "*"`, this effectively grants administrator-equivalent access. Even scoped to a narrow resource ARN, wildcard actions routinely grant far more than intended, since many AWS services expose destructive or privilege-escalating actions (e.g., `iam:*`, `kms:*`, `s3:*`) that a workload has no legitimate reason to call. This is one of the most common IAM over-privilege patterns behind lateral-movement and privilege-escalation paths in real breaches: an attacker who compromises even one credential attached to a wildcard-action policy can pivot far beyond the workload's intended function.

## How Checkov evaluates this
- **Terraform (data check):** for each `statement` block in `aws_iam_policy_document`, if `effect` is `"Allow"` (or unset/`None`, which is the Terraform-plan default for `Allow`) **and** `actions` contains `"*"` → **FAIL**. Otherwise **PASS**.
- **Serverless (function check):** for each statement in the function's `iamRoleStatements`, if `'Action'` is present, contains `"*"`, and `Effect == "Allow"` → **FAIL**. Non-dict statements return `UNKNOWN`. Otherwise **PASS**.
- Statements with `Effect: "Deny"` are never flagged, regardless of the actions wildcard, since a Deny with wildcard actions is a restrictive (not permissive) statement.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["arn:aws:s3:::example-bucket/*"]
  }
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "example" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = ["arn:aws:s3:::example-bucket/*"]
  }
}
```

## Remediation steps
1. Replace the `"*"` action with an explicit, minimal list of the specific API actions the workload actually needs (e.g., `s3:GetObject`, `dynamodb:Query`, `lambda:InvokeFunction`).
2. Use AWS IAM Access Analyzer's policy generation feature (based on CloudTrail activity) to derive the exact set of actions a role has historically used, as a starting point for least-privilege scoping.
3. If broad access is genuinely required for an administrative role, consider using AWS-managed policies (e.g., `PowerUserAccess`) with documented justification rather than an unbounded custom wildcard, and gate it behind break-glass/approval processes.
4. Re-scope the `resources` block as tightly as possible in tandem with narrowing `actions` — a wildcard action combined with a wildcard resource is the worst-case combination.
5. Test thoroughly after narrowing — removing wildcard actions can break functionality that implicitly relied on broader permissions; use IAM policy simulation or a staged rollout.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/StarActionPolicyDocument.py)
- [Checkov check source (Serverless)](https://github.com/bridgecrewio/checkov/blob/main/checkov/serverless/checks/function/aws/StarActionPolicyDocument.py)
- [AWS IAM least privilege documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
