# CKV_AZURE_188: Ensure App configuration Sku is standard

## Severity
**LOW** (score: 2.0/10)

Using a non-standard (e.g., free) SKU is mainly a feature/capacity and support-tier limitation rather than a direct security exposure.

## Summary
This check ensures Azure App Configuration stores use the `standard` SKU rather than the `free` tier, since several important security controls (private networking, customer-managed keys, purge protection) require the standard tier.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_app_configuration`

## Why it matters
The `free` SKU for Azure App Configuration is explicitly limited: it lacks support for Private Link/disabling public network access, customer-managed key encryption, and purge protection — all of which are separately enforced by other Checkov Azure App Configuration checks (e.g. `CKV_AZURE_185`, `CKV_AZURE_186`, `CKV_AZURE_187`). A store provisioned on the `free` SKU is architecturally incapable of meeting those stronger security postures no matter how it's otherwise configured, so it represents a lower security ceiling by construction — not a specific vulnerability, but a foundational limitation that blocks defense-in-depth controls the organization may need. Using `standard` doesn't itself close every gap, but it's the prerequisite that makes the other hardening controls possible at all.

## How Checkov evaluates this
The check performs a simple positive-value comparison of the `sku` attribute against the expected value `"standard"`. If `sku` is set to anything other than `"standard"` (e.g. `"free"`), or missing, the check FAILS. Only `sku = "standard"` PASSES.

## Non-compliant example
```hcl
resource "azurerm_app_configuration" "example" {
  name                = "appconf1"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "free"
}
```

## Remediated example
```hcl
resource "azurerm_app_configuration" "example" {
  name                = "appconf1"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
}
```

## Remediation steps
1. Set `sku = "standard"` on the `azurerm_app_configuration` resource.
2. Note that changing the SKU of an existing App Configuration store from `free` to `standard` is not an in-place update in the Azure control plane in all cases — verify current provider behavior; it may trigger resource replacement depending on the `azurerm` provider version, which would generate a new endpoint/keys and require reconfiguring consumers.
3. Budget for the cost difference — `standard` is a paid tier with usage-based pricing, unlike the free tier's fixed (and limited) capacity.
4. After upgrading, layer on the additional controls that `standard` unlocks: disable public network access, enable purge protection, and configure customer-managed key encryption as appropriate for the workload's sensitivity.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppConfigSku.py
- [Azure App Configuration pricing/SKU documentation](https://learn.microsoft.com/en-us/azure/azure-app-configuration/overview)
