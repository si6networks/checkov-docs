# CKV_AZURE_205: Ensure Azure Service Bus is using the latest version of TLS encryption

## Severity
**HIGH** (score: 7.0/10)

Allowing TLS versions below 1.2 for Service Bus client connections permits weaker, exploitable cryptography to protect potentially sensitive message traffic, enabling on-path interception or tampering.

## Summary
This check ensures an Azure Service Bus namespace enforces TLS 1.2 as its minimum TLS version for client connections.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_servicebus_namespace`

## Why it matters
Older TLS versions (1.0, 1.1) contain known cryptographic weaknesses — vulnerability to protocol downgrade attacks, weaker cipher suite support, and susceptibility to attacks like BEAST and POODLE-adjacent issues. If a Service Bus namespace allows connections negotiated with TLS 1.0/1.1, an attacker capable of interposing on the network path could potentially force or exploit a weaker handshake, undermining the confidentiality and integrity of messages in transit (which may include sensitive business data, PII, or command/control payloads for distributed systems). Enforcing a minimum TLS version of 1.2 ensures all client SDKs and consumers must use modern, well-vetted cryptography, which is also required by many compliance regimes (PCI-DSS forbids TLS below 1.2).

## How Checkov evaluates this
This is a `BaseResourceValueCheck`:
- **Inspected key:** `minimum_tls_version`
- **Expected value:** `"1.2"`
- The check FAILS if `minimum_tls_version` is unset (provider default may allow `"1.0"` depending on provider version) or set to anything other than `"1.2"`, and PASSES only when explicitly `"1.2"`.

## Non-compliant example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"

  minimum_tls_version = "1.0"
}
```

## Remediated example
```hcl
resource "azurerm_servicebus_namespace" "example" {
  name                = "example-namespace"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"

  minimum_tls_version = "1.2"   # enforce modern TLS
}
```

## Remediation steps
1. Set `minimum_tls_version = "1.2"` explicitly on every `azurerm_servicebus_namespace` resource.
2. Verify all client SDKs/libraries connecting to the namespace support TLS 1.2 (essentially all modern SDKs do; only very old client libraries or legacy .NET Framework versions without updated settings may be affected).
3. Test in a non-production namespace first if legacy clients are a concern, since enforcing TLS 1.2 will reject any connection attempting to negotiate a lower version.
4. This is a non-disruptive, in-place attribute update in Terraform (no resource replacement).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServicebusMinTLSVersion.py)
- [Azure Service Bus enforce minimum TLS version documentation](https://learn.microsoft.com/en-us/azure/service-bus-messaging/transport-layer-security-configure-minimum-version)
