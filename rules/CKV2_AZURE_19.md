# CKV2_AZURE_19: Ensure that Azure Synapse workspaces have no IP firewall rules attached

## Severity
**LOW** (score: 2.0/10)

An IP firewall rule permitting broad or unrestricted network access to a Synapse workspace exposes a sensitive analytics/data platform to unauthorized network-level access.

## Summary
This check ensures that Azure Synapse Analytics workspaces do not have any IP-based firewall rules attached, which — combined with Synapse's "Allow Azure services" toggle behavior — implies network access should be governed by managed private endpoints or VNet-based controls rather than broad IP allow-listing.

## Applicability
- **IaC frameworks:** ARM/Bicep and Terraform.
- **Resource types:** `Microsoft.Synapse/workspaces` (ARM/Bicep, Python-based check inspecting `dependsOn`), `azurerm_synapse_workspace` connected to `azurerm_synapse_firewall_rule` (Terraform graph check).

## Why it matters
Synapse workspace firewall rules control which public IP ranges can reach the workspace's SQL endpoints over the public internet. While IP allow-listing feels like a reasonable control, in practice it is brittle and often overly broad: rules are commonly added ad hoc (e.g. `0.0.0.0`–`255.255.255.255` "allow all" for convenience during development and never removed, or wide corporate CIDR ranges that include many untrusted networks like shared office Wi-Fi or third-party VPN exit points). IP-based rules also don't survive well as an organization's network topology changes (dynamic IPs, cloud egress IP churn), leading to either overly permissive rules being kept "just in case" or brittle rules that break legitimate access. The recommended, more robust approach is Private Link/managed virtual network integration, which keeps workspace traffic off the public internet entirely — hence this check flags the *presence* of any IP firewall rule as a signal that the workspace may be relying on the weaker public-network model instead.

## How Checkov evaluates this
Two implementations exist:

**ARM/Bicep** (`AzureSynapseWorkspacesHaveNoIPFirewallRulesAttached.py`), a Python resource check on `Microsoft.Synapse/workspaces`:
```python
def scan_resource_conf(self, conf):
    depends_on = conf.get("dependsOn")
    if depends_on is None or not len(depends_on):
        return CheckResult.PASSED
    if any('Microsoft.Synapse/workspaces/firewallRules' in item for item in depends_on):
        return CheckResult.FAILED
    return CheckResult.PASSED
```
It inspects the workspace resource's `dependsOn` array. If any entry references a `Microsoft.Synapse/workspaces/firewallRules` sub-resource, the workspace fails (it has at least one IP firewall rule attached via ARM's implicit dependency ordering). If `dependsOn` is empty/absent, it passes.

**Terraform** (`AzureSynapseWorkspacesHaveNoIPFirewallRulesAttached.json`), a graph check: PASS requires the `azurerm_synapse_workspace` to have **no** connection to any `azurerm_synapse_firewall_rule` resource. FAIL if any firewall rule is connected to the workspace.

## Non-compliant example
```hcl
resource "azurerm_synapse_workspace" "ws" {
  name                                 = "app-synapse"
  resource_group_name                  = azurerm_resource_group.rg.name
  location                             = azurerm_resource_group.rg.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.dl.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = var.sql_admin_password
}

resource "azurerm_synapse_firewall_rule" "allow_all" {
  name                 = "AllowAll"
  synapse_workspace_id = azurerm_synapse_workspace.ws.id
  start_ip_address     = "0.0.0.0"
  end_ip_address       = "255.255.255.255"
}
```

## Remediated example
```hcl
resource "azurerm_synapse_workspace" "ws" {
  name                                 = "app-synapse"
  resource_group_name                  = azurerm_resource_group.rg.name
  location                             = azurerm_resource_group.rg.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.dl.id
  sql_administrator_login              = "sqladminuser"
  sql_administrator_login_password     = var.sql_admin_password

  managed_virtual_network_enabled = true

  managed_resource_group_name = "synapse-managed-rg"
}

resource "azurerm_synapse_managed_private_endpoint" "storage_pe" {
  name                 = "storage-private-endpoint"
  synapse_workspace_id = azurerm_synapse_workspace.ws.id
  target_resource_id   = azurerm_storage_account.data.id
  subresource_name     = "dfs"
}
# No azurerm_synapse_firewall_rule resources attached
```

## Remediation steps
1. Remove `azurerm_synapse_firewall_rule` resources (or, in ARM/Bicep templates, remove `Microsoft.Synapse/workspaces/firewallRules` child resources and the corresponding `dependsOn` entries).
2. Enable `managed_virtual_network_enabled = true` on the workspace and use `azurerm_synapse_managed_private_endpoint` to reach linked data sources (storage accounts, Key Vault, etc.) privately.
3. If some IP-based access is unavoidable during a migration period, scope firewall rules as tightly as possible (specific, documented IPs/CIDRs — never `0.0.0.0`–`255.255.255.255`) and track them for removal, since the check treats any rule as non-compliant.
4. Removing overly broad firewall rules can break existing client connectivity if those clients aren't using Private Link/VNet integration yet — coordinate with consumers before removing rules to avoid an outage.
5. Review Synapse's "Allow Azure services and resources to access this workspace" setting separately; it also affects the network exposure surface and should be assessed alongside firewall rule removal.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureSynapseWorkspacesHaveNoIPFirewallRulesAttached.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSynapseWorkspacesHaveNoIPFirewallRulesAttached.json)
- [Azure Synapse Analytics: IP firewall rules](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-ip-firewall)
- [Azure Synapse Analytics: Managed private endpoints](https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-private-endpoints)
