# CKV_AZURE_108: Ensure that Azure IoT Hub disables public network access
## Severity
**HIGH** (score: 7.0/10)

Public network access to an IoT Hub exposes a device-management and telemetry control plane to the internet, increasing risk of unauthorized device interaction or data interception.

## Summary
This check ensures that an Azure IoT Hub instance disables public network access so it can only be reached over a private endpoint rather than the public internet.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_iothub` (inspects `public_network_access_enabled`)
- (No ARM/Bicep implementation reported for this specific check.)

## Why it matters
IoT Hub is the central ingestion and device-management point for potentially thousands of field devices, and it typically has access to backend processing pipelines, storage, and other Azure services via routing rules and managed identities. If public network access is left enabled, the hub's device-facing and service-facing endpoints are reachable from anywhere on the internet, increasing exposure to credential-stuffing against device connection strings/SAS tokens, spoofed device telemetry injection, and reconnaissance of hub metadata. Disabling public network access and requiring Private Link connectivity ensures that management and data-plane operations against the hub can only originate from within the trusted network, adding a strong layer of defense beyond device authentication alone.

## How Checkov evaluates this
This check has `missing_block_result=CheckResult.PASSED`. It inspects `public_network_access_enabled` on `azurerm_iothub` and expects it to be `false`. If the attribute is explicitly set to `true`, the check **FAILS**. If the attribute is omitted, Checkov treats this as **PASSED** (note: the actual Azure/provider default for this attribute is `true`/enabled, so relying on the omitted-attribute PASS behavior here means the deployed resource may still have public access enabled in practice — explicitly setting the value is recommended).

## Non-compliant example
```hcl
resource "azurerm_iothub" "bad_example" {
  name                = "bad-iothub"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  sku {
    name     = "S1"
    capacity = "1"
  }

  public_network_access_enabled = true
}
```

## Remediated example
```hcl
resource "azurerm_iothub" "good_example" {
  name                = "good-iothub"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  sku {
    name     = "S1"
    capacity = "1"
  }

  # Fix: explicitly disable public network access
  public_network_access_enabled = false
}

resource "azurerm_private_endpoint" "iothub_pe" {
  name                = "iothub-pe"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.example.id

  private_service_connection {
    name                           = "iothub-privatelink"
    private_connection_resource_id = azurerm_iothub.good_example.id
    subresource_names              = ["iotHub"]
    is_manual_connection           = false
  }
}
```

## Remediation steps
1. Explicitly set `public_network_access_enabled = false` on the `azurerm_iothub` resource (do not rely on omitting the attribute).
2. Create a Private Endpoint for the `iotHub` sub-resource so devices/services on the private network can still connect.
3. Note that disabling public network access affects both device connectivity and management-plane operations (e.g., Azure CLI/Portal access) — ensure operational tooling has a private network path (VPN, ExpressRoute, or jump host) before disabling.
4. Devices without private connectivity (e.g., truly public field devices connecting over the internet) cannot use this hub once public access is disabled — this is only appropriate for hubs consumed exclusively by devices/services inside your private network or via VPN gateways.
5. Update DNS to resolve through the private DNS zone associated with the private endpoint (`privatelink.azure-devices.net`).

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/IoTNoPublicNetworkAccess.py)
- [Azure docs: IoT Hub Private Link support](https://learn.microsoft.com/en-us/azure/iot-hub/virtual-network-support)
