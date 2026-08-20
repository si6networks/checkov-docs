# CKV_AWS_107: Ensure IAM policies does not allow credentials exposure
## Severity
**LOW** (score: 2.0/10)

This check (via Cloudsplaining) flags IAM policies that allow actions capable of exposing credentials (e.g. retrieving/creating access keys or passwords for other identities), which can lead directly to full account takeover and privilege escalation.

## Summary
This check uses the `cloudsplaining` policy-analysis engine to ensure IAM policies do not include actions that could expose sensitive credentials (e.g. IAM access keys, login profile passwords, service-specific credentials) to the policy's principal.

## Applicability
- **Terraform**: `aws_iam_policy_document` data source (analyzed via the underlying compiled policy JSON).
- **CloudFormation**: `AWS::IAM::Group`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy`, `AWS::IAM::Role`, `AWS::IAM::User` resources containing inline or attached IAM policy documents.

## Why it matters
Certain IAM actions allow a principal to create, read, or reset credentials belonging to other IAM identities — for example `iam:CreateAccessKey`, `iam:UpdateLoginProfile`, or `iam:CreateServiceSpecificCredential`. If a policy grants these actions broadly (e.g. against `Resource: "*"` or all users/roles), a principal holding that policy can mint new long-lived AWS access keys for any other IAM user, or reset another user's console password — effectively achieving privilege escalation or full account takeover without needing to compromise that other identity directly. This is one of the most common and dangerous IAM privilege-escalation vectors documented in AWS security research, and cloudsplaining's `credentials_exposure` analysis specifically flags this class of action. The check deliberately excludes `ecr:GetAuthorizationToken`, since that action only returns a short-lived, service-scoped ECR authentication token rather than exposing durable IAM credentials, and is a legitimate, extremely common requirement for ECR access.

## How Checkov evaluates this
Both implementations delegate to the `cloudsplaining` library's `PolicyDocument.credentials_exposure` analysis, which flags specific high-risk IAM actions found in the evaluated policy document, then filters out actions in an explicit exclusion set:
- `excluded_actions = {"ecr:GetAuthorizationToken"}` — this specific action is never reported, even if cloudsplaining's underlying analysis considers it a credentials-exposure action.
- If, after exclusion, any credentials-exposure actions remain in the policy, the check **FAILS** (returns them as findings).
- If the remaining list is empty (no matching actions, or only the excluded ECR action was present), the check **PASSES**.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "risky" {
  statement {
    effect  = "Allow"
    actions = [
      "iam:CreateAccessKey",
      "iam:UpdateLoginProfile",
    ]
    resources = ["*"]
  }
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "scoped" {
  statement {
    effect  = "Allow"
    actions = [
      "iam:CreateAccessKey",
    ]
    resources = ["arn:aws:iam::123456789012:user/${self.name}"]  # only the caller's own user
    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = ["${self.name}"]
    }
  }
}
```

## Remediation steps
1. Remove credentials-exposure actions (e.g. `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:CreateServiceSpecificCredential`, `sts:GetFederationToken`, etc.) from broadly-scoped policies.
2. If such actions are genuinely required (e.g. a self-service credential-rotation tool), scope the `Resource` to the specific principal ARN and add an IAM condition (e.g. `aws:username` equals the caller) so users can only manage their own credentials, never another identity's.
3. Prefer moving away from long-lived IAM access keys altogether — use IAM Identity Center / federated roles with STS temporary credentials, which removes the need for `iam:CreateAccessKey`-style permissions entirely.
4. Run a cloudsplaining scan directly against deployed policies periodically, since this check only covers policies expressible in your IaC — attached AWS-managed policies may need separate review.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/IAMCredentialsExposure.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMCredentialsExposure.py)
- [cloudsplaining project](https://github.com/salesforce/cloudsplaining)
