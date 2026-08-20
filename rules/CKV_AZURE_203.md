# CKV_AZURE_203: Ensure Azure Service Bus Local Authentication is disabled

## Severity
**LOW** (score: 2.0/10)

Leaving local (SAS key) authentication enabled allows access via long-lived, often over-scoped shared keys with no per-identity audit trail, so a single leaked key can grant broad, unattributable send/listen/manage access to the namespace.

## Summary
This check ensures an Azure Service Bus namespace has `local_auth_enabled` set to `false`, forcing all clients to authenticate via Azure AD instead of SAS keys/connection strings.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_servicebus_namespace`

## Why it matters
"Local authentication" for Service Bus refers to Shared Access Signature (SAS) key-based authentication — static, long-lived secrets embedded in connection strings. These keys are frequently over-scoped (namespace-wide "RootManageSharedAccessKey" is a common default), do not support fine-grained per-identity auditing (all actions using the same key look identical in logs), are hard to rotate without breaking clients, and are a favorite target for credential leakage (accidentally committed to git repos, leaked in CI/CD logs, or exposed in client-side code). If an attacker obtains a leaked SAS key, they gain send/listen/manage access to the Service Bus namespace with no way to attribute the individual actor. Disabling local authentication forces all access through Azure AD, enabling conditional access policies, per-principal RBAC scoping, and full audit trails tied to actual identities (users or managed identities) rather than an anonymous shared secret.

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `local_auth_enabled`
- **Expected value:** `False`
- The check FAILS if `local_auth_enabled` is `true` or left at its default (`true` in the `azurerm` provider), and PASSES only when explicitly set to `false`.

## Non-compliant example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"

  local_auth_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"

  local_auth_enabled = false   # SAS-key auth disabled, Azure AD required
}
```

## Remediation steps
1. Set `local_auth_enabled = false` on the `azurerm_servicebus_namespace` resource.
2. Before applying, migrate every client, application, and pipeline that currently authenticates via SAS connection strings to use Azure AD-based authentication (via `DefaultAzureCredential`/managed identity in the client SDK), since existing connection strings stop working immediately once local auth is disabled.
3. Ensure appropriate Azure RBAC role assignments exist for each consumer (`Azure Service Bus Data Sender`, `Azure Service Bus Data Receiver`, or `Azure Service Bus Data Owner` as appropriate) before the cutover.
4. Roll out in a staging/non-production namespace first, and validate every producer/consumer, since this is a breaking change for anything still using connection strings.
5. Combine with CKV_AZURE_202 (enable managed identity) so Azure resources connecting to the namespace can authenticate without any secret at all.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusLocalAuthDisabled.py)
- [Azure Service Bus authentication and authorization documentation](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization)
