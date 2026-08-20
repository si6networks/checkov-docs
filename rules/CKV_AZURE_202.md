# CKV_AZURE_202: Ensure that Managed identity provider is enabled for Azure Service Bus

## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, Service Bus must rely on long-lived static credentials for cross-resource authentication, increasing the chance of credential leakage and complicating revocation, though it does not by itself expose the namespace.

## Summary
This check ensures an Azure Service Bus namespace has a managed identity (`identity` block with a `type`) configured, rather than relying purely on shared access keys/connection strings for authentication to related Azure resources.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azurerm_servicebus_namespace`

## Why it matters
Without a managed identity, Service Bus can't authenticate to other Azure resources (such as Key Vault for CMK, or other services it integrates with) using Azure AD-backed identity — it must fall back on static credentials such as shared access signature (SAS) keys or connection strings. Those static secrets are long-lived, often over-permissioned, easy to leak (checked into source control, embedded in app settings, logged accidentally), and hard to rotate without breaking every consumer that hardcoded them. A managed identity removes the need to store or manage any credential at all: Azure AD issues short-lived tokens automatically, which sharply reduces the attack surface for credential theft and simplifies revocation (disable the identity or its role assignment, rather than hunting down every place a static key was distributed). This is also a prerequisite for using customer-managed keys (CMK) with Service Bus, since Key Vault access requires an identity to authorize against.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `identity/[0]/type`
- **Expected value:** `ANY_VALUE` — any non-empty `type` (e.g. `SystemAssigned`, `UserAssigned`, `SystemAssigned, UserAssigned`) satisfies the check.
- The check FAILS if no `identity` block is present, or the block exists without a `type`.

## Non-compliant example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
  # no identity block configured
}
```

## Remediated example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"

  identity {
    type = "SystemAssigned"   # managed identity enabled
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_servicebus_namespace` resource.
2. Choose `SystemAssigned` for the simplest setup (identity lifecycle tied to the namespace), or `UserAssigned` (referencing an `azurerm_user_assigned_identity`) if you need the identity to be shared across resources or to persist independent of the namespace's lifecycle.
3. Grant the identity the minimum necessary role assignments on any resources it needs to access (e.g. Key Vault Crypto Service Encryption User on the Key Vault for CMK scenarios).
4. Re-apply — adding an identity to an existing namespace is a non-disruptive, in-place update.
5. Migrate any application code still using SAS connection strings to use Azure AD / managed identity-based authentication where feasible.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusIdentityProviderEnabled.py)
- [Azure Service Bus managed identity documentation](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-managed-service-identity)
