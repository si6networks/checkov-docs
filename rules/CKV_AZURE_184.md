# CKV_AZURE_184: Ensure 'local_auth_enabled' is set to 'False'

## Severity
**HIGH** (score: 7.5/10)

Leaving local (access-key based) authentication enabled on App Configuration allows callers to bypass Azure AD identity-based authentication, weakening the ability to enforce centralized, auditable access control over configuration data that often includes secrets and connection strings.

## Summary
This check ensures Azure App Configuration stores disable local (access-key based) authentication, forcing all requests to authenticate via Azure Active Directory instead.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (`azurerm` provider)
- **Resource type:** `azurerm_app_configuration`

## Why it matters
By default, Azure App Configuration supports two authentication schemes: Azure AD (Entra ID) tokens, and static access keys (primary/secondary read-write and read-only keys). Access keys behave like long-lived shared secrets — anyone holding a key can read or write configuration values (which frequently include feature flags, connection strings, or other sensitive settings) with no per-identity audit trail, no conditional access enforcement, and no easy revocation short of rotating the key (which breaks every other consumer using it). If a key leaks — via a config file committed to source control, an exposed CI variable, or a compromised application — an attacker gets full access to the store until the key is rotated. Azure AD authentication, by contrast, supports RBAC scoped per-identity, Conditional Access policies, and short-lived tokens, giving far stronger control and auditability. Disabling local auth removes the access-key attack surface entirely.

## How Checkov evaluates this
The check inspects the `local_auth_enabled` attribute on `azurerm_app_configuration`. It is implemented as a negative-value check with `missing_attribute_result=FAILED`: if the attribute is absent, the check FAILS (fail closed, since the Azure default for this setting is `true`/enabled). If `local_auth_enabled` is explicitly set to `true`, the check FAILS. Only an explicit `local_auth_enabled = false` PASSES.

## Non-compliant example
```hcl
resource "azurerm_app_configuration" "example" {
  name                = "appconf1"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  local_auth_enabled  = true
}
```

## Remediated example
```hcl
resource "azurerm_app_configuration" "example" {
  name                = "appconf1"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  local_auth_enabled  = false
}
```

## Remediation steps
1. Set `local_auth_enabled = false` explicitly on every `azurerm_app_configuration` resource (do not rely on omission — Checkov and Azure both treat the missing/default state as enabled).
2. Migrate all consuming applications and CI/CD pipelines to use Azure AD authentication — assign them an appropriate RBAC role (e.g. `App Configuration Data Reader` or `App Configuration Data Owner`) via managed identity or service principal.
3. Confirm no automation still references the store's access keys before disabling; disabling local auth immediately breaks any client still using a connection string with an embedded key.
4. Requires `azurerm` provider support for `local_auth_enabled` (added in relatively recent provider versions); update the provider if the attribute is unrecognized.
5. This is generally an in-place update (no resource replacement), but plan a short validation window to confirm dependent apps still connect successfully after the change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppConfigLocalAuth.py
- [Azure App Configuration Azure AD authentication documentation](https://learn.microsoft.com/en-us/azure/azure-app-configuration/concept-enable-rbac)
