# CKV_AZURE_25: Azure SQL Server threat detection alerts are enabled for all threat types

## Severity
**HIGH** (score: 7.5/10)

Failing to enable all SQL threat-detection alert types delays detection of active attacks such as SQL injection or anomalous access, an availability/response-time gap rather than a direct exposure of data.

## Summary
This check ensures Azure SQL Server / database threat detection (Advanced Threat Protection security alert policy) is enabled with no threat-detection alert types disabled.

## Applicability
- **Frameworks:** Terraform, Bicep (graph-based check), ARM
- **Resource types:** `Microsoft.Sql/servers`, `Microsoft.Sql/servers/databases`, `Microsoft.Sql/servers/databases/securityAlertPolicies`, `Microsoft.Sql/servers/securityAlertPolicies`, `azurerm_mssql_server_security_alert_policy`

## Why it matters
Azure SQL's threat detection service watches for anomalous activity such as SQL injection attempts, brute-force login attempts, access from unusual locations, and data exfiltration patterns. Each of these detections maps to a distinct "threat type" (e.g., `Sql_Injection`, `Brute_Force`, `Data_Exfiltration`). If the alert policy exists but has specific alert types disabled (via `disabledAlerts` / `disabled_alerts`), or the state is not `Enabled`, the corresponding attack classes go completely unmonitored — an attacker exploiting exactly the disabled category (e.g., SQL injection) triggers no alert at all, giving defenders a false sense of security since "threat detection" appears configured but silently has gaps.

## How Checkov evaluates this
**ARM check** (`SQLServerThreatDetectionTypes`, a `BaseResourceCheck`): iterates nested `resources` under a `Microsoft.Sql/servers/databases` resource, looking for a `securityAlertPolicies` sub-resource. **PASS** only if `properties.state` equals `"enabled"` (case-insensitive) AND `properties.disabledAlerts` is falsy/empty. Otherwise **FAIL**.

**Bicep check**: a graph-based JSON policy that requires the connected `Microsoft.Sql/servers/securityAlertPolicies` (or the database-level equivalent) to exist, have `properties.state` equal to `"Enabled"`, and have `properties.disabledAlerts` either empty or not present.

**Terraform check** (`SQLServerThreatDetectionTypes`, extends `BaseResourceCheck`) inspects `azurerm_mssql_server_security_alert_policy.disabled_alerts`: **FAIL** if `disabled_alerts` is present and any entry is truthy (non-empty); otherwise **PASS**.

## Non-compliant example
```hcl
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mssql_server.example.name
  state               = "Enabled"

  disabled_alerts = [
    "Sql_Injection",   # SQL injection detection turned off
  ]
}
```

## Remediated example
```hcl
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_mssql_server.example.name
  state               = "Enabled"

  disabled_alerts = []   # all threat-detection alert types remain active
}
```

## Remediation steps
1. Ensure the `azurerm_mssql_server_security_alert_policy` (or ARM `securityAlertPolicies` sub-resource) has `state`/`properties.state` set to `Enabled`.
2. Remove all entries from `disabled_alerts` / `properties.disabledAlerts` so every threat category is monitored.
3. Pair this with `CKV_AZURE_26`/`CKV_AZURE_27` (email alert recipients) so detected threats actually reach a human/on-call channel.
4. Consider migrating to Microsoft Defender for SQL (the modern successor to Advanced Threat Protection) if not already using it, as legacy threat-detection policies are being consolidated there.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerThreatDetectionTypes.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SQLServerThreatDetectionTypes.py)
- [Checkov check source (Bicep graph)](https://github.com/bridgecrewio/checkov/blob/main/checkov/bicep/checks/graph_checks/SQLServerThreatDetectionTypes.json)
- [Azure SQL Advanced Threat Protection](https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview)
