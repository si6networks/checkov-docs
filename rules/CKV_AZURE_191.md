# CKV_AZURE_191: Ensure that Managed identity provider is enabled for Azure Event Grid Topic

## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, the Event Grid Topic must rely on other authentication mechanisms (e.g., static keys) to interact with Azure resources, increasing credential-management risk compared to Azure AD-backed identity.

## Summary
This check ensures an Azure Event Grid Topic has a managed identity configured, so it can authenticate to other Azure resources (e.g. event handlers, dead-letter destinations) without static credentials.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform (`azurerm` provider), ARM templates, Bicep (compiled to ARM)
- **Resource types:**
  - ARM: `Microsoft.EventGrid/topics`
  - Terraform: `azurerm_eventgrid_topic`

## Why it matters
Event Grid Topics deliver events to subscriber endpoints and can write dead-lettered events to storage. Without a managed identity, delivery to resources that require authentication (e.g. an Azure Function behind auth, a Service Bus queue, or a storage account for dead-lettering) either has to be left open/unauthenticated or must rely on statically embedded credentials or SAS tokens configured on the destination. Those static secrets face the usual risks: leakage via configuration files, difficulty rotating without breaking delivery, and no per-resource audit trail of which identity performed which delivery. A system- or user-assigned managed identity lets Event Grid authenticate to destinations using short-lived Azure AD tokens, scoped via RBAC to exactly the delivery/dead-letter targets it needs, removing the need to manage or rotate secrets for this integration.

## How Checkov evaluates this
**ARM:** Checks that `identity.type` is set to any non-empty value (`ANY_VALUE` accepted) on the `Microsoft.EventGrid/topics` resource. If the `identity` block or its `type` field is absent, the check FAILS.

**Terraform:** Same logic, checking `identity[0].type` on `azurerm_eventgrid_topic`. Any configured identity type (`SystemAssigned`, `UserAssigned`, or both) PASSES; an absent `identity` block FAILS.

## Non-compliant example
```hcl
resource "azurerm_eventgrid_topic" "example" {
  name                = "example-topic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  # no identity block defined
}
```

## Remediated example
```hcl
resource "azurerm_eventgrid_topic" "example" {
  name                = "example-topic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_eventgrid_topic` resource with `type = "SystemAssigned"` (or `UserAssigned`/both, referencing `identity_ids` for user-assigned identities).
2. Configure event subscriptions' delivery settings to use the managed identity for authenticated delivery (`delivery_identity` on `azurerm_eventgrid_event_subscription`) where the destination supports Azure AD-based delivery, e.g. Service Bus, Storage Queues, or Event Hubs.
3. Grant the managed identity the minimum RBAC role needed on each delivery/dead-letter destination (e.g. `Storage Queue Data Message Sender`, `Azure Event Hubs Data Sender`).
4. This is generally a non-disruptive, in-place update; validate event delivery continues to succeed after switching subscriptions to identity-based authentication before removing any prior key-based configuration.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/EventgridTopicIdentityProviderEnabled.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridTopicIdentityProviderEnabled.py
- [Azure Event Grid managed identity documentation](https://learn.microsoft.com/en-us/azure/event-grid/managed-service-identity)
