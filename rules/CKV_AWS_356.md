# CKV_AWS_356: Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
## Severity
**HIGH** (score: 7.5/10)

Same underlying risk as the resource-level check: an aws_iam_policy_document that allows restrictable actions against a wildcard resource grants unbounded access scope, a common precursor to privilege escalation once the policy is attached to any principal.

## Summary
Flags `aws_iam_policy_document` **data sources** whose rendered policy JSON grants "restrictable" IAM actions against a wildcard `"*"` resource, using the `cloudsplaining` over-permissioning analysis engine. This is the data-source counterpart to CKV_AWS_355.

## Applicability
- **Framework**: Terraform
- **Entity type**: `aws_iam_policy_document` (a Terraform `data` source, not a `resource`)
- **Type**: data check

## Why it matters
`aws_iam_policy_document` is the idiomatic Terraform way to author IAM policy JSON before attaching it to an `aws_iam_policy`, `aws_iam_role_policy`, `aws_s3_bucket_policy`, etc. Because this data source is frequently the single source of truth that many downstream resources reference, a wildcard-resource statement authored here propagates the over-permissioning issue everywhere it's attached. As with CKV_AWS_355, granting actions that support resource-level scoping (e.g. `s3:GetObject`, `dynamodb:GetItem`, `secretsmanager:GetSecretValue`, `kms:Decrypt`) against `Resource = "*"` means the attached principal can act on every matching resource in the account rather than only the ones it needs — inflating the impact of a stolen credential, a bug in application logic, or a compromised dependency running under that principal's identity, and creating a much larger surface for lateral movement/data exposure than the workload's actual requirements justify.

## How Checkov evaluates this
Uses `BaseTerraformCloudsplainingDataIAMCheck`: Checkov renders the `aws_iam_policy_document` data source into its equivalent policy JSON, wraps it in a `cloudsplaining.scan.policy_document.PolicyDocument`, and calls `policy.all_allowed_unrestricted_actions` — identical evaluation logic to CKV_AWS_355, just applied to the data-source form of a policy document rather than an inline/attached resource policy.
- **FAIL**: one or more actions that support resource-level permissions are granted with `Resource = "*"` (or an equivalent wildcard) in any `statement` block.
- **PASS**: every restrictable action's resource is scoped to specific ARNs.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "app_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]   # grants access to every secret in the account
  }
}

resource "aws_iam_policy" "app_permissions" {
  name   = "app-secrets-access"
  policy = data.aws_iam_policy_document.app_permissions.json
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "app_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.app_credentials.arn]   # scoped to the specific secret
  }
}

resource "aws_iam_policy" "app_permissions" {
  name   = "app-secrets-access"
  policy = data.aws_iam_policy_document.app_permissions.json
}
```

## Remediation steps
1. Identify every `aws_iam_policy_document` data source flagged by Checkov, and inspect each `statement` block's `actions` and `resources`.
2. Replace wildcard `resources = ["*"]` with specific ARNs referencing the actual Terraform-managed resources (or well-scoped ARN patterns) that the policy is meant to grant access to.
3. Where a `statement` legitimately combines both restrictable and non-restrictable actions, consider splitting it into separate statements so the non-restrictable ones aren't forced into an artificially scoped (and possibly invalid) resource list.
4. Trace all downstream consumers of the data source (`aws_iam_policy`, `aws_iam_role_policy`, bucket/queue/topic resource policies, etc.) to confirm the fix propagates everywhere the policy JSON is attached.
5. Re-run Checkov/cloudsplaining to confirm the fix; also consider adding a `condition` block (e.g. restricting by tag or source VPC) for defense in depth even after scoping the resource ARN.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/ResourcePolicyDocument.py
- cloudsplaining project: https://github.com/salesforce/cloudsplaining
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
