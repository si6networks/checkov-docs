# CKV_AZURE_195: Ensure that Azure Event Grid Domain local Authentication is disabled

## Severity
**MEDIUM** (score: 5.0/10)

Leaving local (key-based) authentication enabled on an Event Grid Domain allows bypassing Azure AD identity-based access control via long-lived shared keys, increasing the risk of unauthorized event publication or consumption if a key is exposed.

## Summary
This check ensures an Azure Event Grid Domain disables local (key-based) authentication, requiring publishers and management operations to authenticate via Azure Active Directory instead.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_eventgrid_domain`

## Why it matters
Because an Event Grid Domain typically fronts many topics (often mapped one-per-tenant in multi-tenant architectures), a single shared access key protecting the domain represents an outsized amount of risk relative to a single topic's key: if that key leaks, an attacker could potentially publish forged events across every topic in the domain, not just one. Static access keys also provide no per-caller identity or audit trail, and revocation requires rotating the key for every legitimate publisher simultaneously. Disabling local authentication forces all callers onto Azure AD tokens, enabling per-identity RBAC (e.g. `EventGrid Data Sender` scoped to specific topics within the domain), sign-in auditing, and clean, non-disruptive revocation of individual publishers by removing their role assignment.

## How Checkov evaluates this
The check inspects `local_auth_enabled` on `azurerm_eventgrid_domain`, expecting the value `false`. If `local_auth_enabled` is `true`, or the attribute is omitted (Azure's default is enabled), the check FAILS. Only an explicit `local_auth_enabled = false` PASSES.

## Non-compliant example
```hcl
resource "azurerm_eventgrid_domain" "example" {
  name                = "example-domain"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  local_auth_enabled  = true
}
```

## Remediated example
```hcl
resource "azurerm_eventgrid_domain" "example" {
  name                = "example-domain"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  local_auth_enabled  = false
}
```

## Remediation steps
1. Set `local_auth_enabled = false` on the `azurerm_eventgrid_domain` resource.
2. Migrate all publishers to Azure AD authentication, assigning the `EventGrid Data Sender` (or more scoped custom) role to each publishing identity, ideally scoped to the specific topic(s) they need within the domain rather than the whole domain.
3. Confirm no legacy publisher still depends on the domain's shared access keys before disabling, since this is a breaking change for any key-authenticated caller.
4. Given the domain's broader blast radius compared to a single topic, treat this remediation as high priority and validate thoroughly in a staging environment before rolling out to production domains.
5. This is an in-place setting change with no resource replacement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridDomainLocalAuthentication.py
- [Azure Event Grid authentication documentation](https://learn.microsoft.com/en-us/azure/event-grid/authenticate-with-active-directory)
