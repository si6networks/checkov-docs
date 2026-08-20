# CKV2_AZURE_33: Ensure storage account is configured with private endpoint
## Severity
**MEDIUM** (score: 6.0/10)

Without a private endpoint, the storage account's data plane remains reachable via public network paths, increasing the attack surface for data exfiltration or unauthorized access attempts compared to fully private connectivity.

## Summary
This check verifies that an Azure Storage Account has an Azure Private Endpoint connected to it, ensuring blob/file/queue/table data-plane access is not exposed over the public internet.

## Applicability
- **IaC framework:** Terraform (graph-based check)
- **Resource type involved:** `azurerm_storage_account`

## Why it matters
Storage accounts frequently hold sensitive business data, backups, application state, and logs. Without a private endpoint, the storage account's public endpoint is reachable from the internet (gated only by whatever network rules/firewall are configured on the account, which are often left permissive by default or misconfigured). This exposes the account to internet-wide scanning for exposed storage endpoints, brute-forcing of account keys/SAS tokens, and exploitation of any misconfigured public access on individual containers. Placing the storage account behind a private endpoint confines data-plane traffic to the private network, meaning even a leaked key or overly broad container ACL can only be exploited by someone already inside the private network — a substantial reduction in exposed attack surface for one of the most commonly breached Azure resource types.

## How Checkov evaluates this
This is a **graph-based connection check**:
- Filters to `azurerm_storage_account` resources.
- Requires a graph connection from the `azurerm_storage_account` to an `azurerm_private_endpoint` resource.

Any storage account without an associated `azurerm_private_endpoint` resource in the Terraform graph FAILS.

## Non-compliant example
```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # No private endpoint — account is reachable via its public endpoint.
}
```

## Remediated example
```hcl
resource "azurerm_storage_account" "example" {
  name                          = "examplestorageacct"
  resource_group_name           = "example-rg"
  location                      = "eastus"
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  public_network_access_enabled = false
}

resource "azurerm_subnet" "pe" {
  name                              = "private-endpoint-subnet"
  resource_group_name               = "example-rg"
  virtual_network_name              = azurerm_virtual_network.example.name
  address_prefixes                  = ["10.0.4.0/24"]
  private_endpoint_network_policies = "Enabled"
}

# Added: private endpoint for blob data-plane access.
resource "azurerm_private_endpoint" "example" {
  name                = "example-storage-pe"
  location            = "eastus"
  resource_group_name = "example-rg"
  subnet_id           = azurerm_subnet.pe.id

  private_service_connection {
    name                           = "example-storage-privateserviceconnection"
    private_connection_resource_id = azurerm_storage_account.example.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Create a dedicated subnet for private endpoints, sized for the number of endpoints you plan to attach.
2. Add an `azurerm_private_endpoint` resource with a `private_service_connection` targeting the storage account, choosing the correct `subresource_names` for the service(s) in use (`blob`, `file`, `queue`, `table`, `dfs`, `web` — one endpoint per subresource is typically required).
3. Create Private DNS Zones for each subresource in use (e.g., `privatelink.blob.core.windows.net`) linked to the VNet, so clients resolve to the private IP.
4. Set `public_network_access_enabled = false` on the storage account (or scope network rules tightly) once private connectivity is verified — a private endpoint alone does not disable the public endpoint unless access is explicitly restricted.
5. Confirm all consumers (applications, CI/CD, on-prem systems) have network reachability to the private endpoint before disabling public access, to avoid an outage.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureStorageAccConfigWithPrivateEndpoint.json)
- [Use private endpoints for Azure Storage](https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints)
