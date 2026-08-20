# CKV_AWS_111: Ensure IAM policies does not allow write access without constraints

## Severity
**LOW** (score: 2.0/10)

Unconstrained write-access IAM actions let a principal modify or destroy resources broadly across the account, a significant integrity/availability risk even without a direct path to privilege escalation.

## Summary
Fails when an IAM policy grants write/modify-level actions (create, update, delete, put on data-plane resources) over an unconstrained resource scope with no restricting condition.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_iam_policy_document` (data source)
- **CloudFormation**: `AWS::IAM::Group`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy`, `AWS::IAM::Role`, `AWS::IAM::User`

Both implementations delegate to the `cloudsplaining` library.

## Why it matters
Write actions (e.g. `s3:PutObject`, `s3:DeleteObject`, `dynamodb:UpdateItem`, `ec2:TerminateInstances`, `rds:DeleteDBInstance`) allow modification or destruction of data and infrastructure. When granted with `Resource: "*"` and no conditions, any principal holding the policy can write to, overwrite, or delete resources far outside the scope the policy author intended — for example, a policy meant to let a service update its own DynamoDB table instead lets it delete every table in the account. This significantly increases the blast radius of a compromised credential or a misconfigured automation, turning a contained incident into an account-wide data-integrity or availability incident (e.g. ransomware-style mass deletion, unauthorized data tampering, unintended resource termination).

## How Checkov evaluates this
Checkov reads `policy.write_actions_without_constraints` from cloudsplaining's `PolicyDocument`. Cloudsplaining classifies IAM actions by "access level" (using the AWS-published access-level classification: List, Read, Write, Permissions management, Tagging). For each statement whose actions include "Write" level actions:
- If the `Resource` is `"*"` (or otherwise unconstrained) and there is no meaningful `Condition` scoping the statement,

the statement's actions are added to the `write_actions_without_constraints` list. Checkov's check returns `FAILED` if this list is non-empty, `PASSED` otherwise.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "bad" {
  statement {
    sid       = "UnconstrainedWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:DeleteObject", "dynamodb:DeleteItem"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "bad" {
  name   = "broad-write-access"
  policy = data.aws_iam_policy_document.bad.json
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "good" {
  statement {
    sid       = "ScopedWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::app-data-bucket/*"]
  }

  statement {
    sid       = "ScopedDynamoWrite"
    effect    = "Allow"
    actions   = ["dynamodb:DeleteItem"]
    resources = ["arn:aws:dynamodb:us-east-1:123456789012:table/app-table"]
  }
}

resource "aws_iam_policy" "good" {
  name   = "scoped-write-access"
  policy = data.aws_iam_policy_document.good.json
}
```

## Remediation steps
1. Enumerate the statements flagged by cloudsplaining/Checkov and identify which "Write" level actions they grant.
2. Replace `resources = ["*"]` with the specific ARNs (bucket/prefix, table, instance, function, etc.) that the caller actually needs to write to.
3. If the resource ARN genuinely cannot be known ahead of time, add a `Condition` (e.g. `StringEquals` on `aws:ResourceTag/...`, or `s3:prefix`/`s3:x-amz-acl` conditions) that meaningfully restricts the action's effect.
4. Split overly broad policies into multiple narrower statements/policies per resource type rather than one catch-all policy.
5. Re-run the scan to confirm `write_actions_without_constraints` is empty for the policy.
6. Treat this as especially urgent for policies attached to CI/CD roles, Lambda execution roles, or any automation with programmatic, unattended access.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/IAMWriteAccess.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMWriteAccess.py
