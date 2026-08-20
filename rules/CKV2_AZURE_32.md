# CKV2_AZURE_32: Ensure private endpoint is configured to key vault
## Severity
**MEDIUM** (score: 6.0/10)

Without a private endpoint, Key Vault remains reachable over the public endpoint (subject to its own firewall rules), increasing exposure of secrets/keys management traffic compared to a fully private network path.

## Summary
This check verifies that an Azure Key Vault has an Azure Private Endpoint connected to it, ensuring the vault is reachable only over private network paths rather than the public internet.

## Applicability
- **IaC framework:** Terraform (graph-based check)
- **Resource type involved:** `azurerm_key_vault`

## Why it matters
Key Vault stores an organization's most sensitive material — encryption keys, TLS certificates, connection strings, application secrets. Without a private endpoint, the vault's data-plane endpoint is reachable over the public internet (subject to whatever firewall rules are configured, which are often permissive or misconfigured), making it a high-value target for credential-stuffing, network scanning, and exploitation of any authentication misconfiguration. A private endpoint places the vault's data-plane traffic entirely inside the customer's VNet, removing public internet reachability altogether — meaning even a compromised or misconfigured access policy can only be exploited by an attacker who has already achieved a foothold inside the private network, not from anywhere on the internet. This is one of the highest-value network controls for secrets management infrastructure.

## How Checkov evaluates this
This is a **graph-based connection check**:
- Filters to `azurerm_key_vault` resources.
- Requires a graph connection from the `azurerm_key_vault` to an `azurerm_private_endpoint` resource.

Any Key Vault without an associated `azurerm_private_endpoint` resource in the Terraform graph FAILS.

## Non-compliant example
```hcl
resource "azurerm_key_vault" "example" {
  name                = "example-kv"
  location            = "eastus"
  resource_group_name = "example-rg"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  # No private endpoint — the vault's data plane is reachable via its public DNS name.
}
```

## Remediated example
```hcl
resource "azurerm_key_vault" "example" {
  name                          = "example-kv"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  public_network_access_enabled = false
}

resource "azurerm_subnet" "pe" {
  name                                          = "private-endpoint-subnet"
  resource_group_name                           = "example-rg"
  virtual_network_name                          = azurerm_virtual_network.example.name
  address_prefixes                              = ["10.0.3.0/24"]
  private_endpoint_network_policies             = "Enabled"
}

# Added: private endpoint connecting the vault into the VNet.
resource "azurerm_private_endpoint" "example" {
  name                = "example-kv-pe"
  location            = "eastus"
  resource_group_name = "example-rg"
  subnet_id           = azurerm_subnet.pe.id

  private_service_connection {
    name                           = "example-kv-privateserviceconnection"
    private_connection_resource_id = azurerm_key_vault.example.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Create a dedicated subnet for private endpoints (or reuse an existing one) with `private_endpoint_network_policies` set appropriately for your Terraform/azurerm provider version.
2. Add an `azurerm_private_endpoint` resource with a `private_service_connection` block targeting the Key Vault's resource ID and `subresource_names = ["vault"]`.
3. Configure a Private DNS Zone (`privatelink.vaultcore.azure.net`) linked to the VNet so clients resolve the vault's FQDN to the private endpoint's IP rather than the public IP.
4. Set `public_network_access_enabled = false` on the Key Vault (or restrict via network ACLs) once the private endpoint and DNS are verified working — leaving public access enabled alongside a private endpoint still permits internet reachability unless explicitly disabled.
5. Update any CI/CD pipelines, on-prem systems, or other consumers that access the vault to ensure they have network connectivity to the private endpoint (VNet peering, VPN, or ExpressRoute) before cutting off public access.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureKeyVaultConfigPrivateEndpoint.json)
- [Azure Key Vault Private Link](https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service)
