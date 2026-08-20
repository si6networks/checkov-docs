# CKV_AZURE_162: Ensures Spring Cloud API Portal Public Access Is Disabled

## Severity
**HIGH** (score: 7.5/10)

Leaving the Spring Cloud API Portal publicly accessible broadens the network attack surface, letting unauthenticated internet users reach an interface intended for internal or restricted API consumption.

## Summary
This check ensures that an Azure Spring Cloud (Azure Spring Apps) API Portal instance does not have public network access enabled, keeping it reachable only from within the trusted virtual network.

## Applicability
- **Framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_spring_cloud_api_portal`

## Why it matters
The API Portal exposes API documentation and testing capabilities for backend microservices. If public network access is enabled, this developer/administrative surface becomes reachable directly from the internet, which increases the attack surface for reconnaissance (an attacker can enumerate exposed API operations and schemas), authentication brute-forcing, or exploitation of any vulnerability in the portal component itself. Restricting the portal to private/VNET-only access ensures that only users and systems already inside the trusted network perimeter (e.g. via VPN, ExpressRoute, or a jump host) can reach it, consistent with least-exposure design for internal developer tooling.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects `public_network_access_enabled`:
- **FAIL** if the value is `true` (the forbidden value).
- **PASS** if `false` or omitted.

## Non-compliant example
```hcl
resource "azurerm_spring_cloud_api_portal" "example" {
  name                           = "example-portal"
  spring_cloud_service_id        = azurerm_spring_cloud_service.example.id
  public_network_access_enabled  = true   # portal reachable from the internet
}
```

## Remediated example
```hcl
resource "azurerm_spring_cloud_api_portal" "example" {
  name                           = "example-portal"
  spring_cloud_service_id        = azurerm_spring_cloud_service.example.id
  public_network_access_enabled  = false   # restricted to private/VNET access
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on every `azurerm_spring_cloud_api_portal` resource (or omit the attribute, since `false` is the safe default).
2. Ensure the parent Azure Spring Apps service is deployed with VNET injection so private access paths (VPN, ExpressRoute, peered VNETs) exist for legitimate developer/admin access.
3. This is an in-place configuration change and does not require resource replacement.
4. Combine with HTTPS-only enforcement (see CKV_AZURE_161) for layered protection of the portal.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SpringCloudAPIPortalPublicAccessIsDisabled.py)
- [Azure Spring Apps networking documentation](https://learn.microsoft.com/en-us/azure/spring-apps/how-to-deploy-in-azure-virtual-network)
