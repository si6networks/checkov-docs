# CKV_GITHUB_2: Ensure GitHub organization security settings require SSO
## Severity
**HIGH** (score: 7.5/10)

Without an org-wide SSO requirement, members can authenticate with weaker, unmonitored credentials, materially raising the risk of account takeover and unauthorized access to source code and secrets.

## Summary
This check enforces that a GitHub organization has SAML single sign-on (SSO) configured, verified via the presence of a SAML identity provider `ssoUrl` in the organization's security configuration.

## Applicability
Applies to GitHub organization configuration (`github_configuration` IaC type / entity `*`), evaluated against the organization security document (the JSON payload describing organization-level settings, keyed under `data.organization`).

## Why it matters
Without organization-enforced SSO, member authentication is left entirely to each individual GitHub account's own credentials and 2FA settings, which the organization cannot centrally govern. This means the organization has no way to guarantee session lifetime policies, centralized deprovisioning (e.g., instantly cutting off access when an employee is terminated via the IdP), or consistent MFA enforcement across all members. A departing employee's personal GitHub account can retain access to organization repositories and secrets until someone manually removes them, and there is no single point to revoke access org-wide during an incident. SSO tied to a corporate identity provider closes this gap by making repository access dependent on active IdP-managed identity.

## How Checkov evaluates this
The check validates the organization security configuration against a JSON schema (`org_security_schema`), then uses a JSONPath query for `$..data.organization.samlIdentityProvider.ssoUrl`. If that path resolves to at least one value in the configuration (meaning a SAML SSO URL is configured), the check PASSES. If the path is absent (no SSO URL set), it FAILS. If the configuration doesn't match the expected schema at all, the result is UNKNOWN (not evaluated).

## Non-compliant example
```json
{
  "data": {
    "organization": {
      "login": "my-org",
      "samlIdentityProvider": null
    }
  }
}
```

## Remediated example
```json
{
  "data": {
    "organization": {
      "login": "my-org",
      "samlIdentityProvider": {
        "ssoUrl": "https://idp.example.com/sso/saml2"
      }
    }
  }
}
```

## Remediation steps
1. In your GitHub organization settings, go to Settings > Authentication security > SAML single sign-on.
2. Configure the SAML identity provider (e.g., Okta, Azure AD, Google Workspace) with the required IdP issuer, SSO URL, and public certificate.
3. Enable "Require SAML SSO authentication for all members of the organization".
4. Note this feature requires a GitHub Enterprise Cloud plan — organizations on lower tiers cannot enable SSO enforcement.
5. Communicate the SSO enrollment link to all members before enforcing, since unenrolled members lose access to organization resources once enforcement is turned on.
6. Re-run the Checkov GitHub configuration scan to confirm `ssoUrl` now appears in the exported organization security data.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/sso.py)
- [GitHub Docs: About SAML single sign-on](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on)
