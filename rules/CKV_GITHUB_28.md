# CKV_GITHUB_28: Ensure an organization's identity is confirmed with a Verified badge
## Severity
**LOW** (score: 2.0/10)

The Verified badge is a trust/branding signal for consumers of the org's public profile and does not itself control access to code, secrets, or infrastructure.

## Summary
This check enforces that a GitHub organization has completed GitHub's organization verification process, which cryptographically links the org to a verified company domain and displays a "Verified" badge.

## Applicability
**Checkov framework(s):** `github_configuration`

Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated against the organization profile setting `is_verified`.

## Why it matters
An unverified organization provides no independent, GitHub-attested proof that the organization account genuinely belongs to the company it claims to represent. This matters most for supply-chain trust: developers, customers, and automated tooling (package registries, dependency scanners, security researchers) often use organization verification as a signal to distinguish an authentic vendor/company account from a look-alike or typosquatted organization created by an attacker to distribute malicious packages or phish contributors. Without verification, it is easier for an impersonating organization to appear legitimate, and harder for external parties to confirm they are interacting with the real entity, which can undermine trust decisions made downstream (e.g., "is it safe to add this org's action to our workflow?").

## How Checkov evaluates this
The check reads the `is_verified` field from the organization configuration. It passes only when the value is explicitly `True`; any other value, including `False` or a missing attribute (`missing_attribute_result=CheckResult.FAILED`), fails.

## Non-compliant example
```json
{
  "login": "my-org",
  "is_verified": false
}
```

## Remediated example
```json
{
  "login": "my-org",
  "is_verified": true
}
```

## Remediation steps
1. Go to your GitHub organization Settings > Profile (or "Verified domains").
2. Add and verify one or more domains you control that represent your organization (e.g., `example.com`) via the DNS TXT record challenge GitHub provides.
3. Once a domain is verified, GitHub displays the "Verified" badge on the organization's public profile — this is the state the `is_verified` field reflects.
4. This is largely a one-time administrative task (not something reverted by normal engineering work), but re-verify after any DNS provider migration in case the verification TXT record was dropped.
5. Re-run the Checkov GitHub scan to confirm `is_verified` now reports `true`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_verified_organization.py)
- [GitHub Docs: Verifying or approving a domain for your organization](https://docs.github.com/en/organizations/managing-organization-settings/verifying-or-approving-a-domain-for-your-organization)
