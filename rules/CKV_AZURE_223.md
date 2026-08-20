# CKV_AZURE_223: Ensure Event Hub Namespace uses at least TLS 1.2
## Severity
**HIGH** (score: 7.0/10)

Allowing Event Hub Namespace clients to connect below TLS 1.2 permits weak or deprecated transport encryption, exposing streamed event data to interception or downgrade attacks.

## Summary
Ensures that an Azure Event Hubs namespace enforces a minimum TLS version of 1.2 for client connections, rejecting older, weaker TLS versions.

## Applicability
- **Terraform**: `azurerm_eventhub_namespace` — inspects `minimum_tls_version`
- **ARM**: `Microsoft.EventHub/namespaces` — inspects `properties.minimumTlsVersion`
- **Bicep**: compiles to the ARM resource type above

## Why it matters
Event Hubs namespaces accept client connections (producers and consumers) over AMQP/HTTPS, and the `minimumTlsVersion` setting controls the floor of TLS protocol versions the service will negotiate. TLS 1.0 and 1.1 have well-documented cryptographic weaknesses (e.g., susceptibility to BEAST and POODLE-style attacks, weak hash algorithms in the handshake) and have been formally deprecated by major browsers, standards bodies, and compliance frameworks (PCI-DSS explicitly disallows TLS below 1.2). If a namespace still permits clients to connect using TLS 1.0/1.1, message payloads and any embedded application data — which may include telemetry, IoT sensor data, financial transaction events, or other sensitive event stream content — are transmitted with a weaker cryptographic guarantee, increasing the risk of interception or downgrade attacks by an on-path adversary. Enforcing a minimum of TLS 1.2 (or 1.3 where supported) closes this gap and aligns with modern security baselines.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` with `missing_block_result=CheckResult.PASSED`, meaning if the attribute is absent from the config, Checkov treats the check as passing (because Azure's platform default for Event Hub namespaces is already TLS 1.2).
- **Terraform**: inspects `minimum_tls_version`. Expected value is the string `"1.2"`. **PASSES** if set to `"1.2"` (or if the attribute is omitted, per the missing-block default). **FAILS** if explicitly set to a lower version like `"1.0"` or `"1.1"`.
- **ARM**: inspects `properties.minimumTlsVersion`. Same logic.

## Non-compliant example
```hcl
resource "azurerm_eventhub_namespace" "example" {
  name                = "example-ehns"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"

  minimum_tls_version = "1.0"   # allows outdated, weak TLS
}
```

## Remediated example
```hcl
resource "azurerm_eventhub_namespace" "example" {
  name                = "example-ehns"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"

  minimum_tls_version = "1.2"   # enforce modern minimum TLS
}
```

## Remediation steps
1. Set `minimum_tls_version = "1.2"` explicitly (or simply omit the attribute, since Azure's default already enforces 1.2), and never set it to `"1.0"` or `"1.1"`.
2. Audit all producer/consumer clients (SDKs, IoT devices, on-prem integration tools) connecting to the namespace to confirm they support TLS 1.2 before enforcing the minimum — older SDK versions or legacy .NET Framework clients without updated TLS stacks may fail to connect after tightening this setting.
3. Where legacy clients cannot be upgraded quickly, plan a phased migration (client library upgrade, OS-level TLS 1.2 enablement) rather than leaving the namespace permanently at a lower TLS floor.
4. Consider also reviewing associated network security controls (private endpoints, IP firewall rules) for the namespace as complementary hardening alongside TLS enforcement.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/EventHubNamespaceMinTLS12.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventHubNamespaceMinTLS12.py
- Azure docs: https://learn.microsoft.com/en-us/azure/event-hubs/transport-layer-security-enforce-minimum-version
