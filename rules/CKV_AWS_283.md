# CKV_AWS_283: Ensure no IAM policies documents allow ALL or any AWS principal permissions to the resource
## Severity
**HIGH** (score: 7.5/10)

An IAM policy document that grants actions to Principal "*" (or any AWS principal) allows any AWS account, including attackers, to invoke the permitted actions on the resource, effectively removing IAM-based access control.

## Summary
This check fails when an `aws_iam_policy_document` data source contains an `Allow` statement (with no `condition`) whose `principals` block specifies `type = "AWS"` and an `identifiers` list containing the wildcard `"*"`, i.e. a policy that grants access to *any* AWS account/principal.

## Applicability
- **Framework:** Terraform
- **Entity:** `aws_iam_policy_document` (data source)

## Why it matters
An IAM resource-based policy (bucket policy, KMS key policy, SNS/SQS policy, IAM role trust policy, etc.) built from a policy document that allows AWS principal `"*"` without any restricting `condition` effectively makes the resource accessible to **any AWS account in the world**, not just your own. This is one of the most common causes of major cloud data breaches: publicly accessible S3 buckets, KMS keys anyone can use to decrypt data, or IAM roles anyone can assume, all stem from exactly this pattern — a wildcard AWS principal combined with an `Allow` effect and no confining `Condition` (such as `aws:PrincipalOrgID`, `aws:SourceArn`, or `aws:SourceAccount`). The check explicitly permits `Deny` statements with `*` (since denying everyone-by-default with narrow exceptions is a legitimate, safe pattern), but any `Allow` with a bare `AWS: "*"` principal and no condition is treated as a critical over-exposure.

## How Checkov evaluates this
This is a Python `BaseDataCheck` (not a graph JSON policy) that inspects the `statement` blocks of the `aws_iam_policy_document` data source configuration. For each statement, it fails (`CheckResult.FAILED`) if **all** of the following hold: (1) the statement has no `condition` block; (2) the statement's `effect` is not `["Deny"]` (so `Allow`, or unset/default, both count); (3) it contains a `principals` block with `type == "AWS"`; and (4) the `identifiers` list for that principal is itself a list containing `"*"`. If any statement lacks these conditions, or if a condition is present, or the effect is `Deny`, the statement is not flagged; the whole check passes if no statement triggers the failure.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "bad" {
  statement {
    effect  = "Allow"
    actions = ["kms:Decrypt"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    # no condition block -> anyone can decrypt
  }
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "good" {
  statement {
    effect  = "Allow"
    actions = ["kms:Decrypt"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-exampleorgid"]
    }
  }
}
```

## Remediation steps
1. Replace wildcard `identifiers = ["*"]` with the specific account IDs/ARNs/role ARNs that legitimately need access.
2. If a broad principal genuinely is required (e.g., allowing any principal within your AWS Organization), keep `"*"` but add a restricting `condition` block, such as `aws:PrincipalOrgID`, `aws:SourceArn`, or `aws:SourceAccount`, so access is narrowed to a controlled set of callers.
3. For `Deny` statements intended to block everyone except explicit exceptions, this pattern is fine and won't be flagged — verify the statement's `effect` is actually `"Deny"`.
4. Re-run `terraform plan` and check the rendered policy JSON (`terraform console` / `aws_iam_policy_document.json`) to confirm the resulting policy no longer grants unconditional public access.
5. Audit any resource currently using an affected policy document (S3 bucket policy, KMS key policy, SNS topic policy, IAM role trust policy) for signs of unauthorized cross-account access before and after remediation.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/IAMPublicActionsPolicy.py
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
