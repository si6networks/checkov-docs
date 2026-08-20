# CKV_GITHUB_1: Ensure GitHub organization security settings require 2FA
## Severity
**HIGH** (score: 7.5/10)

Not requiring two-factor authentication org-wide leaves every member account, and therefore the org's repositories and secrets, exposed to takeover via credential-stuffing or phishing of a single password.

## Summary
This check fails when a GitHub organization's security settings do not require two-factor authentication (2FA) for all members, checked via the organization's `requiresTwoFactorAuthentication` setting.

## Applicability
**Checkov framework(s):** `github_configuration`

- **Framework:** GitHub organization configuration (`github_configuration` — Checkov's GitHub org/repo settings scanner, driven by data pulled from the GitHub API, not a Terraform/YAML file you author directly)
- **Entities:** organization-level settings (`*`, evaluated against `data/organization/requiresTwoFactorAuthentication`)

## Why it matters
GitHub organization membership grants access to source code, CI/CD secrets, package registries, and (for admins) the ability to change branch protection, webhooks, and third-party app integrations. Password-only authentication is vulnerable to credential stuffing, phishing, and password reuse — all extremely common against developer accounts, which are high-value targets because compromising one developer's GitHub account can lead directly to supply-chain attacks (malicious commits, poisoned releases, exfiltrated secrets from Actions). Enforcing organization-wide 2FA means GitHub will not allow any member (including outside collaborators) to interact with the organization's repositories unless they have 2FA enabled on their personal account, closing off an entire class of account-takeover attacks that rely solely on a stolen or guessed password.

## How Checkov evaluates this
This is implemented as an `OrgSecurity`-based check (`Github2FA`) that reads organization configuration data retrieved from the GitHub API/GraphQL response and evaluates the key `data/organization/requiresTwoFactorAuthentication`. If that boolean field is `true`, the check **PASSES**; if it is `false` (2FA not required at the organization level), the check **FAILS**.

## Non-compliant example
Organization security settings (as reflected in the scanned configuration data) with 2FA requirement disabled:
```json
{
  "data": {
    "organization": {
      "requiresTwoFactorAuthentication": false
    }
  }
}
```
In the GitHub UI, this corresponds to: **Organization Settings → Authentication security → "Require two-factor authentication for everyone in the `<org>` organization"** being unchecked.

## Remediated example
```json
{
  "data": {
    "organization": {
      "requiresTwoFactorAuthentication": true
    }
  }
}
```
In the GitHub UI: check the box for **"Require two-factor authentication for everyone in the `<org>` organization"**.

## Remediation steps
1. As an organization owner, go to **Settings → Authentication security** for the organization.
2. Enable **"Require two-factor authentication for everyone in your organization"**.
3. Before enabling, run GitHub's built-in audit to identify any members/outside collaborators without 2FA enabled — they will lose access immediately (removed from the org) once enforcement is turned on, so notify them in advance to set up 2FA first.
4. Encourage use of a hardware security key or authenticator app (TOTP) over SMS-based 2FA where possible, since SMS is vulnerable to SIM-swapping.
5. If managed via Terraform (`github_organization_settings` or similar provider resources), ensure the corresponding attribute is set and enforced through code review, since this is an org-wide setting Checkov reads from live API data, not from a repo's IaC files directly.
6. Re-run Checkov's GitHub org configuration scan to confirm the setting now reports `true`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/2fa.py
- GitHub documentation on requiring 2FA in an organization: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization
