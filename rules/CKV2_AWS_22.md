# CKV2_AWS_22: Ensure an IAM User does not have access to the console
## Severity
**MEDIUM** (score: 5.0/10)

Console access for programmatic IAM users needlessly expands the credential attack surface (password-based login alongside access keys), but exploitation still requires a separate credential compromise.

## Summary
This check flags any `aws_iam_user` that has an associated `aws_iam_user_login_profile`, meaning the user has been granted AWS Management Console (password-based) login access, rather than being restricted to programmatic (API key) access.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_iam_user` (the entity being validated), `aws_iam_user_login_profile` (the connected resource whose presence causes failure)
- **Check type:** Graph-based connection check

## Why it matters
IAM users intended for automation, service accounts, or programmatic access do not need console (password) login. Provisioning a login profile for such users creates an unnecessary human-usable credential — an additional password that can be phished, brute-forced, reused across sites, or leaked — widening the attack surface for an identity that should only ever be reached via access keys/STS and, ideally, should not be a long-lived IAM user at all. Every login profile is also a target for credential-stuffing and social-engineering attacks against the AWS console, and if MFA is not enforced, a compromised password is enough for full console access. Keeping service/automation IAM users free of console access enforces the principle that humans should authenticate via federated SSO (or at minimum via IAM users explicitly meant for interactive use, ideally with MFA and short session durations), while automation-only identities never touch the console at all.

## How Checkov evaluates this
This is a graph check (`IAMUserHasNoConsoleAccess.json`). It filters resources of type `aws_iam_user`, then requires (as a PASS condition) that **no** connection exists between that `aws_iam_user` and any `aws_iam_user_login_profile` resource (`operator: not_exists`). If a Terraform configuration declares an `aws_iam_user_login_profile` resource whose `user` argument references the IAM user, Checkov's graph builder creates that connection and the check fails for that user.

## Non-compliant example
```hcl
resource "aws_iam_user" "automation_bot" {
  name = "ci-automation-bot"
}

resource "aws_iam_user_login_profile" "automation_bot_login" {
  user    = aws_iam_user.automation_bot.name
  pgp_key = "keybase:some_keybase_username"
}
```

## Remediated example
```hcl
resource "aws_iam_user" "automation_bot" {
  name = "ci-automation-bot"
}

# aws_iam_user_login_profile resource removed entirely —
# the user only has programmatic access via access keys / assumed roles.
resource "aws_iam_access_key" "automation_bot_key" {
  user = aws_iam_user.automation_bot.name
}
```

## Remediation steps
1. Identify which IAM users genuinely need interactive console access (humans) versus which are service/automation accounts (should not).
2. For automation/service users, delete the `aws_iam_user_login_profile` resource referencing them, and remove the console password from the AWS account directly if it was created out-of-band.
3. Rely on `aws_iam_access_key` or, preferably, temporary credentials via IAM roles / STS `AssumeRole` for programmatic access instead of long-lived user passwords.
4. For humans who legitimately need console access, prefer federated access (AWS SSO / IAM Identity Center, SAML) over standalone IAM user login profiles; if a login profile must remain, ensure MFA is enforced (see related checks on MFA enforcement) and `password_reset_required` is set appropriately.
5. Re-apply and confirm the user's console password has actually been removed in the AWS account (destroying the Terraform resource issues an AWS API call to delete the login profile).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/IAMUserHasNoConsoleAccess.json)
- [AWS IAM users guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html)
