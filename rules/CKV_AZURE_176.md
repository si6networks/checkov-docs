# CKV_AZURE_176: Ensure Web PubSub uses managed identities to access Azure resources

## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, Web PubSub must rely on long-lived static credentials/connection strings to reach other Azure resources, increasing the risk of credential leakage and making access harder to audit and rotate compared to identity-based auth.

## Summary
This check ensures that an Azure Web PubSub resource has a managed identity (`identity.type`) configured, rather than relying solely on static, long-lived credentials to authenticate to other Azure resources.

## Applicability
- **Terraform**: `azurerm_web_pubsub` (`identity[0].type`).
- **ARM/Bicep**: `Microsoft.SignalRService/webPubSub` (`identity.type`).

## Why it matters
Without a managed identity, any integration between Web PubSub and other Azure services (e.g., Event Grid for event handling, Key Vault for secrets, storage for logs) must rely on connection strings, access keys, or other static secrets that must be provisioned, distributed, rotated, and protected manually. Static credentials are a persistent liability: if leaked (via source control, logs, or a compromised pipeline), they grant standing access until manually rotated, and rotation is often neglected in practice. A system- or user-assigned managed identity lets Web PubSub authenticate to Azure AD-integrated services using short-lived, automatically-rotated tokens with no secret ever stored in configuration, substantially reducing the credential-exposure attack surface.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` as the expected value — meaning the check simply requires that `identity.type` (Terraform: `identity/[0]/type`; ARM: `identity/type`) be **present and set to any non-empty value** (e.g., `SystemAssigned`, `UserAssigned`, or `SystemAssigned, UserAssigned`). If the `identity` block/property is missing entirely, the check **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_web_pubsub" "pubsub" {
  name                = "my-webpubsub"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard_S1"
  capacity            = 1
  # No identity block configured
}
```

## Remediated example
```hcl
resource "azurerm_web_pubsub" "pubsub" {
  name                = "my-webpubsub"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard_S1"
  capacity            = 1

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Add an `identity` block with `type = "SystemAssigned"` (simplest, one identity tied to the resource lifecycle) or `"UserAssigned"` (for identities shared/managed independently of the resource) to the `azurerm_web_pubsub` resource.
2. Grant the resulting managed identity the minimum necessary RBAC role assignments on the target Azure resources it needs to reach (e.g., Event Grid, Key Vault) instead of continuing to distribute connection strings.
3. Update any event handler / upstream configuration that previously used access-key-based auth to use the managed identity where supported.
4. For `UserAssigned`, also configure `identity_ids` referencing the user-assigned identity resource(s).
5. This does not by itself remove access-key-based authentication — separately consider disabling local/key-based auth if the service supports it, once managed-identity-based flows are validated.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PubsubSpecifyIdentity.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/PubsubSpecifyIdentity.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/azure-web-pubsub/howto-use-managed-identity
