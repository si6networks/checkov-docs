# CKV_AZURE_194: Ensure that Managed identity provider is enabled for Azure Event Grid Domain

## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, the Event Grid Domain must depend on statically managed credentials to authenticate to other Azure resources, increasing the risk of credential leakage and complicating least-privilege access.

## Summary
This check ensures an Azure Event Grid Domain has a managed identity configured, so it can authenticate to other Azure resources without relying on static credentials.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_eventgrid_domain`

## Why it matters
An Event Grid Domain acts as a management/routing point for a large number of topics, often used at scale (e.g. per-tenant or per-customer topics in a SaaS product). Like a single Event Grid Topic, a Domain may need to deliver events to protected destinations (storage for dead-lettering, Service Bus, Functions) or interact with other Azure resources during event routing. Without a managed identity, that integration must fall back to static, shared credentials embedded in configuration — a single leaked credential could then be used to affect delivery across every topic under that domain, which, given a Domain's typically large blast radius (potentially hundreds or thousands of topics), makes the consequences of credential leakage significantly worse than for a single topic. A managed identity provides per-resource, short-lived, revocable authentication instead, scoped tightly via RBAC.

## How Checkov evaluates this
The check inspects `identity[0].type` on the `azurerm_eventgrid_domain` resource. It accepts `ANY_VALUE` — any configured identity type (`SystemAssigned`, `UserAssigned`, or both) PASSES. If the `identity` block is absent, the check FAILS.

## Non-compliant example
```hcl
resource "azurerm_eventgrid_domain" "example" {
  name                = "example-domain"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  # no identity block defined
}
```

## Remediated example
```hcl
resource "azurerm_eventgrid_domain" "example" {
  name                = "example-domain"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_eventgrid_domain` resource with `type = "SystemAssigned"` (or `UserAssigned`/both).
2. Configure delivery settings on domain topics/subscriptions to use the managed identity for authenticated delivery to destinations that support Azure AD-based delivery.
3. Grant the identity the minimum RBAC roles needed on downstream delivery/dead-letter targets (e.g. `Storage Queue Data Message Sender`).
4. Given a Domain's larger blast radius, prioritize this remediation across all domains, and pair it with disabling local authentication (see `CKV_AZURE_195`) for a complete hardening pass.
5. This is generally a non-disruptive, in-place update; validate delivery continues to succeed for all downstream topics after enabling identity-based authentication.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridDomainIdentityProviderEnabled.py
- [Azure Event Grid domains documentation](https://learn.microsoft.com/en-us/azure/event-grid/event-domains)
