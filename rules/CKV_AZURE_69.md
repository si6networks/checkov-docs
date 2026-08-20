# CKV_AZURE_69: Ensure that Azure Defender is set to On for Azure SQL database servers
## Severity
**LOW** (score: 2.0/10)

Without Defender for SQL, attacks against a high-value data store such as SQL injection, brute-force login, or anomalous bulk extraction generate no dedicated security alert, substantially increasing attacker dwell time.

## Summary
This check fails when the Azure Security Center (Microsoft Defender for Cloud) pricing tier for the "SqlServers" resource type is not set to "Standard", meaning Defender for SQL is not enabled for the subscription's Azure SQL database servers.

## Applicability
Applies to Terraform, for the resource type `azurerm_security_center_subscription_pricing`.

## Why it matters
Microsoft Defender for SQL provides SQL-specific threat detection (anomalous access patterns, potential SQL injection, brute-force login attempts, unusual data extraction) and vulnerability assessment (detecting misconfigurations, excessive permissions, and unpatched vulnerabilities within the database). SQL databases are among the highest-value targets for attackers because they directly store an organization's structured business data, often including credentials, PII, and financial records. Without this Defender plan enabled, a successful SQL injection attack, a compromised application credential used for unusual bulk data extraction, or a brute-force attempt against SQL authentication would generate no dedicated security alert — the organization would be relying entirely on application-level logging (if any) to notice the compromise, substantially increasing dwell time for an attacker inside the database.

## How Checkov evaluates this
The check inspects the `azurerm_security_center_subscription_pricing` resource's `resource_type` and `tier` attributes. It PASSES if `resource_type` is anything other than `"SqlServers"` (a different Defender plan, not this check's target) OR if `resource_type == "SqlServers"` and `tier == "Standard"`. It FAILS only when `resource_type == "SqlServers"` and `tier` is not `"Standard"` (e.g. `"Free"` or unset).

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "SqlServers"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"  # enables Microsoft Defender for SQL
  resource_type = "SqlServers"
}
```

## Remediation steps
1. Set `tier = "Standard"` on the `azurerm_security_center_subscription_pricing` resource with `resource_type = "SqlServers"`.
2. This is a subscription-wide setting protecting all Azure SQL logical servers in the subscription — no per-database configuration needed.
3. Confirm cost implications: Defender for SQL is billed per protected server/managed instance.
4. After enabling, review and act on Vulnerability Assessment findings that Defender for SQL surfaces (e.g. weak authentication settings, excessive permissions, unencrypted sensitive columns).
5. Route Defender for SQL alerts to your SIEM/Sentinel for timely triage; enabling the tier without a response process limits its practical value.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnSqlServers.py)
- [Azure docs: Microsoft Defender for SQL](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction)
