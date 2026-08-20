# CKV2_AZURE_55: Ensure Azure Spring Cloud app end-to-end TLS is enabled

## Severity
**HIGH** (score: 7.5/10)

Disabling end-to-end TLS on Azure Spring Cloud app traffic allows sensitive application data to be transmitted or intercepted in cleartext between components, a real confidentiality risk for data in transit.

## Summary
This check verifies that apps deployed in an Azure Spring Cloud (now Azure Spring Apps) service on a non-Basic tier have end-to-end TLS enabled between the ingress and the application instance.

## Applicability
- **Terraform**: `azurerm_spring_cloud_service` and its connected `azurerm_spring_cloud_app` resources.

This is a graph-based connection/attribute check spanning two related resource types.

## Why it matters
Azure Spring Cloud terminates TLS at the ingress by default; without end-to-end TLS enabled, traffic between the ingress/load balancer and the actual application instance travels in plaintext inside the platform's internal network. While this internal segment is generally more trusted than the public internet, disabling end-to-end encryption still creates exposure to anyone with access to the underlying network fabric, violates defense-in-depth and zero-trust principles, and is frequently a required control for compliance frameworks (PCI-DSS, HIPAA) that mandate encryption of all data in transit, not just the public-facing hop. It's also a common oversight since the default configuration often does not enable it automatically.

## How Checkov evaluates this
Implemented as a JSON graph query. The check effectively short-circuits (passes) in cases where TLS enforcement doesn't apply to this check's scope, and otherwise requires each `azurerm_spring_cloud_app` to opt into TLS:

- PASS (out of scope): `azurerm_spring_cloud_service.sku_tier` is not set, or is set to `"Basic"` (the Basic tier is exempted from this check).
- Otherwise, for a non-Basic tier service:
  - PASS: the service has no connected `azurerm_spring_cloud_app` resources at all (nothing to check).
  - PASS: every connected `azurerm_spring_cloud_app` has `tls_enabled` present and set to `true`.
  - FAIL: a connected `azurerm_spring_cloud_app` exists where `tls_enabled` is absent or `false`.

## Non-compliant example
```hcl
resource "azurerm_spring_cloud_service" "example" {
  name                = "example-springcloud"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "S0"
  sku_tier            = "Standard"
}

resource "azurerm_spring_cloud_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  service_name        = azurerm_spring_cloud_service.example.name
  # tls_enabled not set -> defaults to false -> FAILS
}
```

## Remediated example
```hcl
resource "azurerm_spring_cloud_service" "example" {
  name                = "example-springcloud"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "S0"
  sku_tier            = "Standard"
}

resource "azurerm_spring_cloud_app" "example" {
  name                = "example-app"
  resource_group_name = azurerm_resource_group.example.name
  service_name        = azurerm_spring_cloud_service.example.name
  tls_enabled         = true   # added: end-to-end TLS
}
```

## Remediation steps
1. For any `azurerm_spring_cloud_service` on a Standard/Enterprise SKU tier, set `tls_enabled = true` on every associated `azurerm_spring_cloud_app`.
2. Ensure the application itself is configured to serve/accept TLS on its internal port, since enabling this at the Terraform level requires the app to actually support it.
3. If you intentionally use the Basic tier and don't need this control, no change is needed — Checkov exempts Basic tier by design.
4. Re-deploy/apply — enabling TLS on an existing app may briefly interrupt connections during the config change; test in a non-production environment first.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureSpringCloudTLSDisabled.json)
- [Azure Spring Apps end-to-end TLS documentation](https://learn.microsoft.com/en-us/azure/spring-apps/how-to-enable-end-to-end-tls)
