# CKV_LIN_3: Ensure email is set

## Severity
**LOW** (score: 1.5/10)

Requiring an email address on a Linode user is an account-hygiene/contactability control with no direct bearing on access control or exploitability.

## Summary
This check ensures every Linode Cloud Manager user resource (`linode_user`) has an `email` attribute defined, so each account is tied to a verifiable, contactable identity.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `linode_user`
- **Check type:** resource-configuration attribute check

## Why it matters
Linode uses the account email address for security-critical communications: login notifications, password-reset flows, billing alerts, and abuse/incident notices. A `linode_user` resource provisioned without an `email` value is either invalid at apply time or, in automation, may end up pointing at a placeholder/shared address that nobody monitors. That breaks the ability to detect account compromise (no unauthorized-access alert reaches a real owner), breaks password recovery (no one can complete "forgot password" for that account), and weakens accountability — you cannot map an account to a specific individual for audit/offboarding purposes. Requiring the field to be explicitly set in code forces engineers to consciously assign a real, traceable address to every provisioned user rather than leaving it to chance or a manual console step.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `email` attribute on `linode_user` resources. It passes if `email` is present with any non-empty value (`ANY_VALUE`), and fails if the attribute is missing or empty. Checkov does not validate that the value is a syntactically correct email address — only that something is present.

## Non-compliant example
```hcl
resource "linode_user" "developer" {
  username    = "jdoe"
  restricted  = true
  # email attribute omitted
}
```

## Remediated example
```hcl
resource "linode_user" "developer" {
  username    = "jdoe"
  email       = "jane.doe@example.com"
  restricted  = true
}
```

## Remediation steps
1. Add an `email` argument to every `linode_user` resource block.
2. Use a real, monitored mailbox for the individual or service the account represents — not a shared/generic alias that no one actively reads.
3. If users are provisioned from a directory or HR system, source the email from that system of record (e.g. via a Terraform variable or data source) so it stays accurate as staff join/leave.
4. Combine with an offboarding process that removes or updates `linode_user` resources (and their `email`) when someone leaves, since Checkov only checks presence, not currency, of the value.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/linode/user_email_set.py)
- [Linode Terraform provider: linode_user](https://registry.terraform.io/providers/linode/linode/latest/docs/resources/user)
