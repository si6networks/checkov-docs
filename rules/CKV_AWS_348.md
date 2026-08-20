# CKV_AWS_348: Ensure IAM root user does not have Access keys
## Severity
**HIGH** (score: 7.5/10)

Long-lived access keys on the AWS root user provide unrestricted, unconditional programmatic access to the entire account that cannot be scoped down by IAM policy, making their compromise equivalent to full account takeover.

## Summary
Ensures Terraform-managed `aws_iam_access_key` resources are never created for the `root` account user.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework**: Terraform
- **Resource type**: `aws_iam_access_key`

## Why it matters
The AWS account root user has unrestricted, unbounded permissions across the entire account — it cannot be restricted by an IAM policy and bypasses virtually every guardrail an organization puts in place for regular IAM principals. Long-lived programmatic access keys for the root user are one of the highest-value targets an attacker can obtain: unlike a compromised IAM role or user, root credentials cannot be contained by permission boundaries, SCPs (in most cases), or resource policies, and can be used to disable security controls (CloudTrail, GuardDuty, Config), delete resources, alter billing, or close the account. AWS's own security best practices explicitly state the root user should have no access keys at all — day-to-day and even administrative operations should go through IAM users/roles with MFA and scoped permissions, with the root account locked away (password + hardware MFA) for the rare break-glass actions that truly require it (e.g. changing the support plan, closing the account). Provisioning a root access key in Terraform also means the credential material is likely to end up in state files, CI logs, or version control history.

## How Checkov evaluates this
This is a Terraform "negative value" check that inspects the `user` attribute on `aws_iam_access_key`:
- **FAIL**: `user = "root"` (the forbidden value) — this is the literal string used to reference the root account.
- **PASS**: `user` is set to anything else (a named IAM user), or omitted.

## Non-compliant example
```hcl
resource "aws_iam_access_key" "root_key" {
  user = "root"
}
```

## Remediated example
```hcl
resource "aws_iam_user" "automation" {
  name = "ci-automation"
}

resource "aws_iam_access_key" "automation_key" {
  user = aws_iam_user.automation.name   # scoped IAM user, not root
}
```

## Remediation steps
1. Search your Terraform code and state for any `aws_iam_access_key` resource referencing `user = "root"` and remove it — Terraform should never manage root credentials at all.
2. If root access keys already exist in the live AWS account (created manually, outside Terraform), deactivate and delete them immediately via the AWS Management Console/IAM root credential page — root access keys should not exist in any account, managed by Terraform or not.
3. Replace the intended use case with a dedicated, least-privilege IAM user or role (or better, an IAM Identity Center / assumed-role workflow) and issue access keys against that principal instead.
4. Enable hardware or virtual MFA on the root account and, ideally, do not retain a root password at all for programmatic workflows — reserve root strictly for the small set of actions that require it.
5. Add an account-level GuardDuty/Config rule or AWS Organizations SCP to alert on or block root access key creation going forward, as defense in depth beyond this Terraform-time check.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMUserRootAccessKeys.py
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#lock-away-credentials
