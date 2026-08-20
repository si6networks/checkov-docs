# CKV_AZURE_180: Ensure that data explorer uses Sku with an SLA

## Severity
**LOW** (score: 2.0/10)

This check only flags a Kusto (Data Explorer) cluster SKU that lacks an availability SLA, which is a service-availability/reliability concern rather than a confidentiality, integrity, or access-control gap.

## Summary
This check ensures an Azure Data Explorer (Kusto) cluster is not deployed on a "Dev (No SLA)" SKU, so that the cluster is backed by a production SLA.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_kusto_cluster`

## Why it matters
Azure Data Explorer offers "Dev(No SLA)" SKUs (e.g. `Dev(No SLA)_Standard_D11_v2`, `Dev(No SLA)_Standard_E2a_v4`) intended purely for development/testing. These SKUs come with no availability guarantee from Microsoft and are typically single-instance, non-redundant deployments. If a production workload — or any workload with an uptime/reliability requirement — is deployed on a No-SLA SKU, there is no contractual or architectural guarantee of availability: a single node failure or maintenance event can cause an unplanned, unbounded outage with no recourse. This is a reliability/availability control rather than a confidentiality control, but it directly affects incident response expectations and business continuity planning.

## How Checkov evaluates this
The check is a "negative value" check: it inspects the `sku[0].name` attribute of the `azurerm_kusto_cluster` resource. If the value is one of the forbidden values — `"Dev(No SLA)_Standard_D11_v2"` or `"Dev(No SLA)_Standard_E2a_v4"` — the check FAILS. Any other SKU name (i.e., a standard/paid SKU) PASSES. If the `sku` block or `name` attribute is missing entirely, the check result is `UNKNOWN` (not automatically a failure), since Checkov can't be certain what SKU would be applied by default.

## Non-compliant example
```hcl
resource "azurerm_kusto_cluster" "example" {
  name                = "kustocluster"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Dev(No SLA)_Standard_D11_v2"
    capacity = 1
  }
}
```

## Remediated example
```hcl
resource "azurerm_kusto_cluster" "example" {
  name                = "kustocluster"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    name     = "Standard_D11_v2"  # production SKU with SLA
    capacity = 2
  }
}
```

## Remediation steps
1. Identify any `azurerm_kusto_cluster` resources using a `Dev(No SLA)_*` SKU name.
2. Change the `sku.name` to a standard production SKU (e.g. `Standard_D11_v2`, `Standard_D12_v2`, `Standard_E2a_v4`, etc.) appropriate for your workload's compute/storage needs.
3. Review the `capacity` (node count) setting — production clusters typically run with 2+ nodes for redundancy.
4. Note that changing the SKU on an existing cluster may require Azure to provision new nodes and can incur downtime or additional cost; plan a maintenance window if modifying a live cluster.
5. Reserve `Dev(No SLA)` SKUs strictly for non-production/sandbox environments, and consider tagging or separating those environments so this check can be scoped or suppressed only where appropriate (e.g. via Checkov skip comments on dev-only files).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataExplorerSKUHasSLA.py
- [Azure Data Explorer pricing tiers documentation](https://learn.microsoft.com/en-us/azure/data-explorer/manage-cluster-choose-sku)
