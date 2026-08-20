# CKV_AZURE_79: Ensure that Azure Defender is set to On for SQL servers on machines

## Severity
**LOW** (score: 2.0/10)

Disabled Defender for SQL-on-machines removes a detective control for threats against SQL Server workloads, delaying discovery of an active compromise rather than creating a direct exposure itself.

## Summary
This check ensures the Microsoft Defender for Cloud pricing tier for the `SqlServerVirtualMachines` resource type is set to `Standard` (i.e. Defender for SQL servers on machines is enabled), rather than left on the free tier.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_security_center_subscription_pricing`
- **ARM/Bicep**: `Microsoft.Security/pricings`

## Why it matters
SQL Server instances running on IaaS virtual machines (as opposed to Azure SQL Database/Managed Instance PaaS) do not automatically get the platform-level threat protection that PaaS SQL services have. Microsoft Defender for SQL servers on machines adds vulnerability assessment and, importantly, advanced threat protection that detects anomalous activity indicative of SQL injection attempts, brute-force login attacks, unusual data exfiltration patterns, and privilege escalation — the kinds of attacks that a compromised or exposed SQL Server VM is most at risk from. Without it on, an attacker who gains a foothold or exploits a SQL vulnerability against a self-managed SQL Server VM may operate undetected for far longer, since there's no dedicated database-layer anomaly detection layered on top of generic VM monitoring.

## How Checkov evaluates this
The check inspects the `azurerm_security_center_subscription_pricing` resource's `resource_type` (Terraform) or `name`/`properties.tier` fields (ARM). It fails specifically when `resource_type` (or `name` in ARM) equals `"SqlServerVirtualMachines"` AND `tier` is NOT `"Standard"` (in ARM logic) — note the ARM and Terraform implementations differ slightly in exact boolean structure but both converge on: pricing for the `SqlServerVirtualMachines` resource type must be `Standard` to pass. Any other resource type is unaffected (passes) regardless of tier.

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "SqlServerVirtualMachines"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"   # enables Defender for SQL servers on machines
  resource_type = "SqlServerVirtualMachines"
}
```

## Remediation steps
1. Set `tier = "Standard"` on the `azurerm_security_center_subscription_pricing` resource with `resource_type = "SqlServerVirtualMachines"`.
2. This is a subscription-wide setting — one resource block typically covers the whole subscription, so coordinate with other teams before changing it.
3. Be aware that enabling Defender for SQL on machines incurs additional per-node cost; check current Microsoft Defender for Cloud pricing before enabling broadly.
4. No resource replacement or downtime is required; the change applies at the subscription/plan level.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnSqlServerVMS.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureDefenderOnSqlServersVMS.py
- Azure docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction
