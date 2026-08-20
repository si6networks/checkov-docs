# CKV_AZURE_192: Ensure that Azure Event Grid Topic local Authentication is disabled

## Severity
**MEDIUM** (score: 5.0/10)

Leaving local (key-based) authentication enabled on an Event Grid Topic allows event publishing/consumption via long-lived shared access keys instead of Azure AD, weakening centralized identity control and increasing the blast radius if a key leaks.

## Summary
This check ensures an Azure Event Grid Topic disables local (key-based) authentication, requiring all publishers to authenticate via Azure Active Directory instead.

## Applicability
- **Frameworks:** Terraform (`azurerm` provider), ARM templates, Bicep (compiled to ARM)
- **Resource types:**
  - ARM: `Microsoft.EventGrid/topics`
  - Terraform: `azurerm_eventgrid_topic`

## Why it matters
Event Grid Topics support publishing events using either a shared access key or Azure AD authentication. Access keys are static, long-lived secrets: any application or script holding the key can publish arbitrary events to the topic, with no per-caller identity, no fine-grained authorization, and no easy way to revoke a single publisher's access without rotating the key for every publisher. If a key leaks (via source control, logs, or a compromised host), an attacker can inject forged events into downstream processing pipelines, potentially triggering unintended workflows, poisoning data pipelines, or exhausting downstream resources. Disabling local authentication forces all publishers to use Azure AD tokens, enabling per-identity RBAC (`EventGrid Data Sender`), auditability via Azure AD sign-in logs, and straightforward revocation by removing a role assignment rather than rotating a shared key used by every publisher.

## How Checkov evaluates this
**ARM:** Checks `properties.disableLocalAuth` on `Microsoft.EventGrid/topics`. The check expects this to be `true`. If it's `false` or absent, the check FAILS.

**Terraform:** Checks `local_auth_enabled` on `azurerm_eventgrid_topic`, expecting `false`. If `local_auth_enabled` is `true` or unset (Azure's default is enabled), the check FAILS. Only an explicit `local_auth_enabled = false` PASSES.

## Non-compliant example
```hcl
resource "azurerm_eventgrid_topic" "example" {
  name                = "example-topic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  local_auth_enabled  = true
}
```

## Remediated example
```hcl
resource "azurerm_eventgrid_topic" "example" {
  name                = "example-topic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  local_auth_enabled  = false
}
```

## Remediation steps
1. Set `local_auth_enabled = false` on the `azurerm_eventgrid_topic` resource (`properties.disableLocalAuth: true` in ARM/Bicep).
2. Migrate all event publishers (applications, Azure services, scripts) from access-key-based publishing to Azure AD authentication, assigning them the `EventGrid Data Sender` RBAC role scoped to the topic.
3. Confirm no legacy publisher still depends on the topic's access keys before disabling — disabling immediately rejects any key-authenticated publish requests.
4. Update client SDKs/configuration to acquire and present Azure AD tokens (via managed identity or service principal) for publishing, rather than the topic's endpoint key.
5. This is an in-place setting change with no resource replacement, but treat it as a breaking change for any remaining key-based publishers and validate in a lower environment first.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/EventgridTopicLocalAuthentication.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridTopicLocalAuthentication.py
- [Azure Event Grid authentication documentation](https://learn.microsoft.com/en-us/azure/event-grid/authenticate-with-active-directory)
