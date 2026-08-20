# CKV_AZURE_139: Ensure ACR set to disable public networking
## Severity
**HIGH** (score: 7.5/10)

Leaving public network access enabled on an Azure Container Registry exposes the registry's management and data endpoints directly to the internet, broadening the attack surface for the images and any embedded credentials it stores.

## Summary
This check ensures an Azure Container Registry has public network access disabled, so the registry's data-plane and management-plane endpoints are reachable only via private connectivity (private endpoints/VNet).

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **ARM**: `Microsoft.ContainerRegistry/registries` resources, property `properties/publicNetworkAccess`.
- **Terraform**: `azurerm_container_registry` resource, attribute `public_network_access_enabled`.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
A container registry reachable over the public internet is exposed to credential-based attacks (brute-forcing or replaying leaked service-principal/token credentials against `login.<registry>.azurecr.io`), broad reconnaissance/enumeration of repository names, and DDoS. Since registries store the exact software artifacts that get deployed into production, unauthorized access — even "just" pull access, if credentials are compromised — can leak proprietary code or facilitate a supply-chain attack via a maliciously pushed image if push credentials are also compromised. Restricting network access to Private Link/VNet-only removes the internet as an attack vector entirely: even a leaked credential is far less useful to an external attacker who has no network path to the registry's private endpoint.

## How Checkov evaluates this
Both variants are `BaseResourceValueCheck`s:
- **ARM**: inspects `properties/publicNetworkAccess` and expects the literal string `"Disabled"` to PASS.
- **Terraform**: inspects `public_network_access_enabled` and expects `False` to PASS.
Any other value — including the attribute being absent (provider/ARM default is enabled/public) — FAILS.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"
  # public_network_access_enabled left at default (true) -- FAILS
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"

  public_network_access_enabled = false  # requires Premium SKU for private endpoints

  network_rule_bypass_option = "AzureServices"
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` (Terraform) or `properties.publicNetworkAccess: "Disabled"` (ARM/Bicep).
2. Private endpoints for ACR require the **Premium** SKU — upgrade the SKU first if currently on Basic/Standard, since the check would fail-open on a lower tier without private endpoint support.
3. Create an `azurerm_private_endpoint` targeting the registry's `registry` sub-resource, and link a private DNS zone (`privatelink.azurecr.io`) so internal clients resolve to the private IP.
4. Update AKS/CI/CD/build-agent networking so they route to the registry over the private endpoint (VNet peering, ExpressRoute/VPN for on-prem build agents, etc.) before disabling public access, to avoid breaking existing pipelines.
5. If Azure DevOps/Container Registry tasks running in Azure-hosted agents need access, consider `network_rule_bypass_option = "AzureServices"` as a scoped exception rather than leaving public access enabled broadly.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/ACRPublicNetworkAccessDisabled.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRPublicNetworkAccessDisabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/container-registry/container-registry-private-link
