# CKV_AZURE_4: Ensure AKS logging to Azure Monitoring is Configured

## Severity
**LOW** (score: 2.0/10)

Without AKS diagnostic logging to Azure Monitor, control-plane and workload events needed to detect compromise, lateral movement, or misuse inside the Kubernetes cluster are never captured.

## Summary
This check verifies that an Azure Kubernetes Service (AKS) cluster has the Azure Monitor container insights add-on (`oms_agent`/`omsagent`) enabled, so cluster and container logs/metrics are shipped to a Log Analytics workspace.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_kubernetes_cluster`
- **ARM templates**: `Microsoft.ContainerService/managedClusters`
- **Bicep**: `Microsoft.ContainerService/managedClusters`

## Why it matters
Without Container Insights (the `omsagent`/`oms_agent` add-on) enabled, an AKS cluster produces no centralized record of container stdout/stderr logs, node/pod performance metrics, or cluster-level Kubernetes events in Azure Monitor. This severely hampers both operational troubleshooting (diagnosing crash loops, resource exhaustion, node failures) and security monitoring (detecting anomalous container behavior, privilege escalation attempts, or crypto-mining workloads via unusual CPU/log patterns). Many compliance frameworks require centralized, tamper-resistant logging for containerized workloads; a cluster with no monitoring add-on is effectively a blind spot where malicious activity inside a pod can go completely unnoticed until it causes visible external impact.

## How Checkov evaluates this
- **ARM**: FAILS immediately if `apiVersion == "2017-08-31"` (that API version predates add-on profile support). Otherwise inspects `properties.addonProfiles.omsagent` (checking both `omsagent` and `omsAgent` casing) and PASSES only if that object exists and its `enabled` field is truthy.
- **Terraform**: Supports both older and newer `azurerm` provider schemas. It checks `addon_profile[0].oms_agent[0].enabled` (provider v2.x schema) — if present, PASS/FAIL follows that boolean. If that path doesn't exist, it checks `oms_agent[0].log_analytics_workspace_id` (provider v3.x+ schema, where `oms_agent` is a top-level block and its mere presence with a workspace ID implies logging is configured) — if found, PASSES. If neither path exists, FAILS.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_log_analytics_workspace" "example" {
  name                = "example-law"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
}

resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  }
}
```

## Remediation steps
1. Create (or identify an existing) `azurerm_log_analytics_workspace` to receive AKS telemetry.
2. Add an `oms_agent` block (azurerm provider v3+) or `addon_profile { oms_agent { enabled = true, log_analytics_workspace_id = ... } }` (older provider versions) to the `azurerm_kubernetes_cluster` resource, referencing the workspace ID.
3. In ARM/Bicep, set `properties.addonProfiles.omsagent.enabled = true` and supply `properties.addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID`.
4. Enabling this add-on typically does not require cluster recreation but does trigger an in-place cluster update; plan for a short reconciliation window.
5. After enabling, configure Container Insights alerts/workbooks in the Log Analytics workspace to actually act on the collected data — enabling collection alone doesn't provide detection without follow-on alerting.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AKSLoggingEnabled.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLoggingEnabled.py)
- [Azure Monitor Container Insights overview](https://learn.microsoft.com/en-us/azure/azure-monitor/containers/container-insights-overview)
