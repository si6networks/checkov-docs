# CKV_AWS_110: Ensure IAM policies does not allow privilege escalation

## Severity
**MEDIUM** (score: 5.0/10)

IAM policies that allow privilege escalation actions let a compromised or over-privileged identity grant itself broader permissions, directly enabling full account takeover.

## Summary
Fails when an IAM policy contains a combination of actions that is a known privilege-escalation vector — i.e., a set of permissions that lets the holder grant themselves broader access than originally intended.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_iam_policy_document` (data source)
- **CloudFormation**: `AWS::IAM::Group`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy`, `AWS::IAM::Role`, `AWS::IAM::User`

Both implementations delegate to the `cloudsplaining` library's privilege-escalation detection.

## Why it matters
IAM privilege escalation is one of the most common paths to full AWS account compromise starting from a limited foothold. Well-documented escalation techniques (see Rhino Security Labs' research, which cloudsplaining's ruleset is based on) include combinations such as:
- `iam:CreatePolicyVersion` (create a new default policy version with admin permissions on a policy you're already attached to)
- `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` (pass a privileged role to a new Lambda you then invoke)
- `iam:AddUserToGroup` (add yourself to a privileged group)
- `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` (rewrite a role's trust policy to let yourself assume it)
- `ec2:RunInstances` + `iam:PassRole` (launch an EC2 instance with a privileged instance profile and extract credentials from it)

If an IAM policy grants any of these action combinations without adequate resource/condition restrictions, a low-privileged attacker who compromises the identity holding that policy can pivot to administrator-level access, defeating the principle of least privilege entirely.

## How Checkov evaluates this
Checkov reads the parsed policy via cloudsplaining's `PolicyDocument.allows_privilege_escalation` property. Cloudsplaining matches the statement's granted actions (with unconstrained/broad resources) against its curated list of ~20+ known privilege-escalation "action combinations." Each match returns either a list of action names or a list of dicts (each with an `"actions"` key describing which specific actions triggered the match); Checkov's code flattens either shape into a single list. If that flattened list is non-empty, the check result is `FAILED`; otherwise `PASSED`.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "bad" {
  statement {
    sid       = "PrivEscViaPolicyVersion"
    effect    = "Allow"
    actions   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "bad" {
  name   = "vulnerable-to-privesc"
  policy = data.aws_iam_policy_document.bad.json
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "good" {
  statement {
    sid       = "ScopedPolicyVersionMgmt"
    effect    = "Allow"
    actions   = ["iam:CreatePolicyVersion"]
    resources = ["arn:aws:iam::123456789012:policy/team-app-policy"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Team"
      values   = ["app-team"]
    }
  }
}

resource "aws_iam_policy" "good" {
  name   = "hardened-policy"
  policy = data.aws_iam_policy_document.good.json
}
```

## Remediation steps
1. Run `checkov` or `cloudsplaining scan` against the policy and inspect which specific action combination was flagged — the remediation differs per escalation path.
2. Scope the `Resource` element to the exact ARNs the identity legitimately needs (not `"*"`), so the dangerous action combination cannot be exercised against arbitrary IAM resources.
3. Where `iam:PassRole` is involved, add an `iam:PassedToService` condition restricting which service the role can be passed to.
4. For `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion`, restrict to specific managed policy ARNs and consider requiring a permissions boundary on any role that can perform this action.
5. Avoid attaching wildcard `iam:*` or `*` action statements to non-admin roles entirely — split administrative IAM management into a separate, tightly audited role.
6. Re-scan to confirm the finding clears; treat any remaining flagged combination as a high-severity finding requiring manual security review, not just automatic dismissal via a skip comment.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/IAMPrivilegeEscalation.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/IAMPrivilegeEscalation.py
