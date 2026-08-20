# CKV_GITHUB_3: Ensure GitHub organization security settings has IP allow list enabled
## Severity
**HIGH** (score: 7.0/10)

Without an IP allow list, GitHub app access to the organization is reachable from any network location, removing a meaningful barrier against credential-based account takeover.

## Summary
This check enforces that a GitHub organization has the IP allow list feature enabled for installed GitHub Apps, restricting which network locations can use those apps' credentials to interact with the organization.

## Applicability
Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated against the organization security settings document, specifically `data.organization.ipAllowListForInstalledAppsEnabledSetting`.

## Why it matters
GitHub Apps installed in an organization (CI/CD integrations, bots, third-party tools) often hold broad, long-lived credentials/tokens capable of reading or writing repository content, managing webhooks, or accessing secrets. If those tokens are ever leaked (e.g., via a compromised CI runner, a leaked app private key, or a supply-chain compromise of the app vendor itself), an attacker anywhere on the internet can use the stolen credentials to authenticate as that installed app. An IP allow list closes this gap by requiring that requests authenticated as an installed app originate only from pre-approved network ranges (e.g., the organization's own CI infrastructure or office network), so a leaked token alone is not sufficient for a remote attacker to use it — they would also need network-level access to an allow-listed IP.

## How Checkov evaluates this
The check queries the organization security configuration using a JSONPath expression for `data.organization.ipAllowListForInstalledAppsEnabledSetting` and compares its resolved value against the expected value `"ENABLED"`. If the setting equals `"ENABLED"`, the check passes; any other value (e.g., `"DISABLED"`) or a missing value causes a failure, based on the shared `OrgSecurity` base check's comparison logic.

## Non-compliant example
```json
{
  "data": {
    "organization": {
      "ipAllowListForInstalledAppsEnabledSetting": "DISABLED"
    }
  }
}
```

## Remediated example
```json
{
  "data": {
    "organization": {
      "ipAllowListForInstalledAppsEnabledSetting": "ENABLED"
    }
  }
}
```

## Remediation steps
1. In your GitHub organization Settings > Authentication security (or "IP allow list"), enable "Enable IP allow list".
2. Add the specific CIDR ranges/IP addresses your CI/CD runners, offices, and any legitimate automation sources use.
3. Explicitly enable "Enable IP allow list configuration for installed GitHub Apps" so the restriction also applies to app-based access, not just interactive user sessions.
4. Test carefully before fully rolling out — an incomplete allow list can lock out legitimate CI jobs or remote/VPN-based developers; consider a staged rollout with monitoring.
5. This feature requires GitHub Enterprise Cloud.
6. Re-run the Checkov GitHub scan to confirm the setting reports `ENABLED`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/ipallowlist.py)
- [GitHub Docs: Managing allowed IP addresses for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/managing-allowed-ip-addresses-for-your-organization)
