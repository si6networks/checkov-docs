# CKV_AZURE_189: Ensure that Azure Key Vault disables public network access

## Severity
**CRITICAL** (score: 9.5/10)

Allowing public network access to Azure Key Vault exposes an internet-reachable endpoint for secrets, keys, and certificates, making it a high-value target where a single misconfigured access policy could lead to full secret exfiltration.

## Summary
This check ensures an Azure Key Vault either disables public network access entirely or, if public access remains enabled, at least restricts it via network ACLs (IP rules or virtual network subnet restrictions).

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform (`azurerm` provider), ARM templates, Bicep (compiled to ARM)
- **Resource types:**
  - ARM: `Microsoft.KeyVault/vaults`
  - Terraform: `azurerm_key_vault`

## Why it matters
Key Vault stores the organization's most sensitive secrets: encryption keys, certificates, connection strings, and application secrets. If a Key Vault is reachable from any internet address with no network restriction, its entire security model reduces to authentication and authorization (Azure AD + access policies/RBAC) — with no network-layer backstop. A leaked or misconfigured access token, an overly broad access policy, or a bug in an application that exposes vault operations could be exploited from anywhere in the world. Restricting network access — via Private Endpoint, service endpoints, or explicit IP allow-lists — means that even if credentials are compromised, an attacker outside the trusted network typically cannot reach the vault's data plane at all, providing critical defense-in-depth for the most sensitive resource in most Azure environments.

## How Checkov evaluates this
**ARM:** Reads `properties.publicNetworkAccess`. If it's explicitly `"Disabled"` (case-insensitive), the check PASSES. Otherwise, it falls back to checking `properties.networkAcls.ipRules` — if that list is present and non-empty (i.e. IP-based restrictions are configured even though public access is nominally still on), it still PASSES. If neither condition is met, it FAILS.

**Terraform:** Reads `public_network_access_enabled`. If it's explicitly `false`, PASSES. Otherwise, it inspects the `network_acls` block: if either `ip_rules` or `virtual_network_subnet_ids` is non-empty, it PASSES (network ACLs are considered a sufficient restriction even with public access nominally enabled). If none of the above, it FAILS. Note the Terraform default for `public_network_access_enabled` is `true` when unset, so an empty/default configuration with no `network_acls` FAILS.

## Non-compliant example
```hcl
resource "azurerm_key_vault" "example" {
  name                = "examplekeyvault"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  # public_network_access_enabled defaults to true, no network_acls configured
}
```

## Remediated example
```hcl
resource "azurerm_key_vault" "example" {
  name                            = "examplekeyvault"
  location                        = azurerm_resource_group.example.location
  resource_group_name             = azurerm_resource_group.example.name
  tenant_id                       = data.azurerm_client_config.current.tenant_id
  sku_name                        = "standard"
  public_network_access_enabled   = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on the `azurerm_key_vault` resource (or `properties.publicNetworkAccess: "Disabled"` in ARM/Bicep).
2. Provision an `azurerm_private_endpoint` for the vault so trusted VNet resources retain connectivity via Private Link.
3. If full public disablement isn't yet feasible, at minimum configure a `network_acls` block with `default_action = "Deny"` and explicit `ip_rules`/`virtual_network_subnet_ids` allow-listing only known trusted sources.
4. Verify no CI/CD pipelines, external partners, or admin workstations rely on unrestricted public access before applying — they'll need VPN/ExpressRoute connectivity, an allow-listed IP, or a self-hosted agent inside the VNet afterward.
5. This is generally an in-place update, but disabling public access on a live vault can immediately break existing integrations — validate Private Endpoint/network ACL connectivity first in a lower environment.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/KeyVaultDisablesPublicNetworkAccess.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultDisablesPublicNetworkAccess.py
- [Azure Key Vault network security documentation](https://learn.microsoft.com/en-us/azure/key-vault/general/network-security)
