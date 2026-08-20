# CKV_AWS_273: Ensure access is controlled through SSO and not AWS IAM defined users

## Severity
**LOW** (score: 2.0/10)

Standalone IAM users typically rely on long-lived static access keys that bypass centralized SSO deprovisioning, MFA/conditional-access enforcement, and unified audit trails, making credential leakage and orphaned access materially more likely over time.

## Summary
This check enforces that access to AWS should be granted via federated SSO (e.g., AWS IAM Identity Center / SAML federation) rather than standalone IAM users — it flags every `aws_iam_user` resource unconditionally as a finding, since the mere existence of an IAM user represents a non-SSO access path.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: resource `aws_iam_user` (any and all instances)

## Why it matters
Long-lived IAM users are typically associated with long-lived, static credentials (access keys) that are easy to leak (committed to source control, embedded in CI configs, logged accidentally) and hard to rotate consistently across an organization. They also don't benefit from centralized identity lifecycle management: when an employee leaves or changes role, IAM users must be manually found and disabled/deleted across every account, whereas SSO-federated access is deprovisioned centrally the moment the identity provider revokes the user. IAM users also sidestep MFA-at-login and conditional access policies typically enforced by an SSO/IdP layer, and they don't get the same centralized audit trail (who logged in when, from where) that federated access provides. AWS's own security best practices explicitly recommend using IAM Identity Center (or another SSO/federation mechanism) for human access, reserving IAM users only for narrow service-account cases that truly cannot use temporary, federated credentials.

## How Checkov evaluates this
This check's Terraform implementation (`IAMUserNotUsedForAccess`) is intentionally blunt: `scan_resource_conf` unconditionally returns `CheckResult.FAILED` for every `aws_iam_user` resource, with no condition on any attribute. In other words: **any presence of an `aws_iam_user` resource in Terraform triggers this finding** — there is no configuration that makes an IAM user "pass" this check. This is a policy statement ("don't use IAM users for access") encoded as an always-fail check, meant to be individually reviewed/suppressed per legitimate service-account exception rather than universally "fixed" via a config tweak.

## Non-compliant example
```hcl
resource "aws_iam_user" "recorder_user" {
  name = "tailscale-ssh-session-recorder"
}
```
(This will fail regardless of any other configuration on the resource — there is no attribute that satisfies the check.)

## Remediated example
```hcl
# Preferred: migrate human access to SSO/IAM Identity Center permission sets
# instead of an IAM user. For a genuine machine/service credential need
# where IAM Identity Center federation isn't viable, use a scoped IAM role
# assumed via STS instead of a standalone user with static keys:

resource "aws_iam_role" "recorder_service_role" {
  name = "tailscale-ssh-session-recorder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }  # or the appropriate trusted principal
      Action    = "sts:AssumeRole"
    }]
  })
}

# If an aws_iam_user genuinely cannot be avoided (e.g., a legacy third-party
# integration that only supports static access keys), document the exception
# explicitly and suppress with justification:
resource "aws_iam_user" "recorder_user" {
  name = "tailscale-ssh-session-recorder" #checkov:skip=CKV_AWS_273:Tailscale SSH session recorder integration requires static IAM user credentials; reviewed 2026-08, key rotated quarterly
}
```

## Remediation steps
1. For any human user needing AWS console/CLI access, migrate them to AWS IAM Identity Center (or your existing SAML/OIDC IdP federation) with appropriately scoped permission sets — do not create `aws_iam_user` resources for people.
2. For machine-to-machine access, prefer IAM roles assumed via STS (EC2 instance profiles, ECS task roles, Lambda execution roles, or `sts:AssumeRoleWithWebIdentity` for external systems) instead of static IAM user access keys.
3. For the specific `recorder_user` resource found in this repo, evaluate whether Tailscale's SSH session recorder supports role-based/temporary credentials instead of a static IAM user; check current Tailscale documentation, since many third-party integrations have added AssumeRole support over time.
4. If a static IAM user is unavoidable for a legitimate, narrow reason, add an inline `#checkov:skip=CKV_AWS_273:<justification>` comment (or a `.checkov.yaml` skip entry) documenting why, and ensure the user's permissions are least-privilege and its access keys are rotated on a defined schedule.
5. Track and periodically re-review all suppressed instances of this check, since IAM users are a common long-term credential-leakage risk that can be forgotten once suppressed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/IAMUserNotUsedForAccess.py
- AWS documentation: https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html
