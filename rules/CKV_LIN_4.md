# CKV_LIN_4: Ensure username is set

## Severity
**LOW** (score: 1.5/10)

Requiring a username to be explicitly set is a configuration-completeness/hygiene check rather than a control that closes an actual attack path.

## Summary
This check ensures every Linode Cloud Manager user resource (`linode_user`) has a `username` attribute explicitly defined, so each provisioned account has a unique, identifiable login name.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `linode_user`
- **Check type:** resource-configuration attribute check

## Why it matters
The `username` is the primary identifier Linode uses for login, API tokens, event logs, and audit trails. If it is omitted or left blank in the resource definition (which typically would fail Terraform apply anyway, or could resolve to an empty/ambiguous value through interpolation), you lose the ability to reliably attribute account actions to a specific person or service in Linode's audit log and access reviews. This matters for incident response (who did what) and for least-privilege administration (which restricted user has which grants) — an unnamed or ambiguously-named account undermines both. Enforcing the field at the IaC level catches configuration mistakes (e.g. an interpolated variable resolving to empty string) before they reach a live account.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `username` attribute on `linode_user` resources. It passes if `username` is present with any non-empty value (`ANY_VALUE`), and fails if the attribute is missing or empty.

## Non-compliant example
```hcl
resource "linode_user" "svc_account" {
  email      = "svc-deploy@example.com"
  restricted = true
  # username attribute omitted
}
```

## Remediated example
```hcl
resource "linode_user" "svc_account" {
  username   = "svc-deploy"
  email      = "svc-deploy@example.com"
  restricted = true
}
```

## Remediation steps
1. Add an explicit `username` argument to every `linode_user` resource.
2. Adopt a consistent naming convention (e.g. `svc-<purpose>`, `firstname.lastname`) so accounts are easy to attribute during audits.
3. If username is derived from a variable/data source, verify it can never resolve to an empty string (e.g. add a `validation` block on the input variable).
4. Avoid reusing usernames across environments/accounts to keep audit trails unambiguous.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/linode/user_username_set.py)
- [Linode Terraform provider: linode_user](https://registry.terraform.io/providers/linode/linode/latest/docs/resources/user)
