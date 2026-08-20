# CKV_AZURE_109: Ensure that key vault allows firewall rules settings
## Severity
**MEDIUM** (score: 5.0/10)

Without a default-deny firewall rule, Key Vault (which stores secrets, keys, and certificates) is reachable from any network, removing a key layer of defense-in-depth for one of the most sensitive services in an Azure environment.

## Summary
This check ensures that an Azure Key Vault's network ACLs are configured with a default action of `Deny`, so access is blocked by default unless explicitly allowed by a firewall rule or VNet rule.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_key_vault` (inspects `network_acls[0].default_action`)
- **ARM/Bicep**: `Microsoft.KeyVault/vaults` (inspects `properties/networkAcls/defaultAction`)

## Why it matters
Key Vault stores cryptographic keys, secrets, and certificates that are often the most sensitive assets in an environment — database credentials, TLS private keys, API tokens, encryption keys. If the vault's network ACL default action is `Allow`, the vault is reachable from any network (subject only to Azure AD authentication and access-policy/RBAC checks), meaning a leaked or overly-broad service principal credential can be exploited from anywhere on the internet. Setting the default action to `Deny` and explicitly allow-listing trusted VNets/IP ranges enforces network-layer segmentation as a second control alongside identity-based authorization — so even a compromised credential is useless unless the attacker also has network-level access to an allow-listed source.

## How Checkov evaluates this
- **Terraform**: inspects `network_acls[0].default_action`; expects the string `"Deny"`. If the `network_acls` block is missing, or `default_action` is `"Allow"` (or anything other than `"Deny"`), the check **FAILS**.
- **ARM**: inspects `properties/networkAcls/defaultAction`; same expected value `"Deny"`.

## Non-compliant example
```hcl
resource "azurerm_key_vault" "bad_example" {
  name                = "bad-keyvault"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}
```

## Remediated example
```hcl
resource "azurerm_key_vault" "good_example" {
  name                = "good-keyvault"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  network_acls {
    # Fix: deny by default, allow only explicitly trusted networks
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = ["203.0.113.0/24"]
    virtual_network_subnet_ids = [azurerm_subnet.example.id]
  }
}
```

## Remediation steps
1. Add (or update) the `network_acls` block on `azurerm_key_vault` with `default_action = "Deny"`.
2. Populate `ip_rules` and/or `virtual_network_subnet_ids` with the specific trusted ranges/subnets that legitimately need access.
3. Set `bypass = "AzureServices"` if trusted first-party Azure services (e.g., resource providers acting on your behalf) need access; use `"None"` for the strictest posture if not required.
4. Consider Private Endpoints instead of/alongside network ACLs for the strongest isolation, since Private Link avoids exposing any public endpoint at all.
5. Apply this change carefully in production — flipping `default_action` to `Deny` without first allow-listing legitimate callers (CI/CD runners, application subnets, admin workstations) will cause an outage; stage the rollout and verify allow-lists before enforcing.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/KeyVaultEnablesFirewallRulesSettings.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesFirewallRulesSettings.py)
- [Azure docs: Configure Azure Key Vault networking settings](https://learn.microsoft.com/en-us/azure/key-vault/general/how-to-azure-key-vault-network-security)
