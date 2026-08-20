# CKV_AZURE_158: Ensure Databricks Workspace data plane to control plane communication happens over private link

## Severity
**LOW** (score: 2.0/10)

Allowing Databricks data-plane-to-control-plane traffic over the public internet instead of a private link broadens the network attack surface for a service that handles sensitive data processing workloads.

## Summary
This check ensures that an Azure Databricks workspace does not have public network access enabled, so that data-plane-to-control-plane communication (and all workspace access) occurs over a private link/private endpoint rather than the public internet.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_databricks_workspace`
  - ARM/Bicep: `Microsoft.Databricks/workspaces`

## Why it matters
Databricks workspaces process and often store highly sensitive data (raw and processed datasets, ML models, credentials/secrets used by notebooks). When public network access is enabled, the workspace's control plane and data plane can communicate over the public internet, and the workspace UI/API can be reachable from any address unless separately firewalled — significantly expanding the attack surface for credential-stuffing, exploitation of any workspace/API vulnerabilities, and interception risk. Using Azure Private Link ensures all traffic between the data plane (compute in your VNET) and control plane (Databricks-managed) stays on Microsoft's private backbone network, never traversing the public internet, which substantially reduces exposure to network-based attacks and satisfies stricter network-isolation compliance requirements.

## How Checkov evaluates this
**Terraform** (`BaseResourceNegativeValueCheck`):
- Inspects `public_network_access_enabled` on `azurerm_databricks_workspace`.
- **FAIL** if the value is `true`, or if the attribute is missing entirely (`missing_attribute_result=CheckResult.FAILED`).
- **PASS** if explicitly `false`.

**ARM/Bicep** (custom `BaseResourceCheck`):
- Looks up `properties.publicNetworkAccess` anywhere in the resource config (via `find_in_dict`).
- **FAIL** if the value is missing or equals `"Enabled"`.
- **PASS** only if it is present and set to something other than `"Enabled"` (i.e., `"Disabled"`).

## Non-compliant example
```hcl
resource "azurerm_databricks_workspace" "example" {
  name                = "example-databricks"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "premium"

  public_network_access_enabled = true   # control plane traffic can traverse public internet
}
```

## Remediated example
```hcl
resource "azurerm_databricks_workspace" "example" {
  name                = "example-databricks"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "premium"

  public_network_access_enabled = false   # forces private link connectivity

  network_security_group_rules_required = "NoAzureDatabricksRules"

  custom_parameters {
    virtual_network_id                                   = azurerm_virtual_network.example.id
    private_subnet_name                                  = azurerm_subnet.private.name
    public_subnet_name                                   = azurerm_subnet.public.name
    public_subnet_network_security_group_association_id  = azurerm_subnet_network_security_group_association.public.id
    private_subnet_network_security_group_association_id = azurerm_subnet_network_security_group_association.private.id
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess: "Disabled"` (ARM/Bicep) on the workspace.
2. Requires SKU `premium` — Private Link is not available on the `standard` SKU.
3. Deploy a Private Endpoint for the workspace (`azurerm_private_endpoint`) targeting both the `databricks_ui_api` and `browser_authentication` sub-resources as needed, and configure private DNS zones so name resolution routes to the private endpoint.
4. Configure `custom_parameters` for VNET injection (the workspace must be VNET-injected to fully support private connectivity for both control-plane and data-plane traffic).
5. This is a significant architectural change (VNET injection + private endpoints) typically requiring workspace recreation if converting an existing public workspace — plan for migration/downtime.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DatabricksWorkspaceIsNotPublic.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/DatabricksWorkspaceIsNotPublic.py)
- [Azure Databricks Private Link documentation](https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/private-link/)
