# CKV_AZURE_245: Ensure that Azure Container group is deployed into virtual network

## Severity
**HIGH** (score: 7.5/10)

A publicly-addressed Azure Container Instance is directly reachable from the internet, exposing any application ports to unauthenticated attackers and bypassing NSGs and perimeter firewalls.

## Summary
This check ensures that an Azure Container Instance (ACI) container group does not receive a public IP address, forcing it to be reachable only from inside a private virtual network or with no exposed network endpoint at all.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_container_group`

## Why it matters
Azure Container Instances with a public IP address (`ip_address_type = "Public"`) get a directly internet-routable address for the container group. Any exposed ports become reachable from anywhere on the internet, bypassing network segmentation, NSGs, and perimeter firewalls that protect the rest of the environment. This is a common source of exposure for internal tooling, debug endpoints, or misconfigured services (e.g., a container that binds an admin API on `0.0.0.0` without authentication). Deploying the container group into a private virtual network (or using no address at all) keeps traffic confined to routes and security groups you control, letting you apply NSGs, private endpoints, and Azure Firewall/UDR policies before exposing anything externally.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `ip_address_type` attribute on `azurerm_container_group`:
- **PASS** if `ip_address_type` is `"Private"` or `"None"`.
- **FAIL** if `ip_address_type` is `"Public"` (or any other value not in the allowed list, including when it is left at its provider default of `"Public"`).

## Non-compliant example
```hcl
resource "azurerm_container_group" "example" {
  name                = "aci-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  ip_address_type     = "Public"
  os_type             = "Linux"

  container {
    name   = "example-app"
    image  = "nginx:latest"
    cpu    = "1"
    memory = "1.5"

    ports {
      port     = 443
      protocol = "TCP"
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_container_group" "example" {
  name                = "aci-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  ip_address_type     = "Private"          # was "Public"
  subnet_ids          = [azurerm_subnet.aci.id]
  os_type             = "Linux"

  container {
    name   = "example-app"
    image  = "nginx:latest"
    cpu    = "1"
    memory = "1.5"

    ports {
      port     = 443
      protocol = "TCP"
    }
  }
}
```

## Remediation steps
1. Set `ip_address_type = "Private"` and attach the container group to a delegated subnet via `subnet_ids` (a subnet delegated to `Microsoft.ContainerInstance/containerGroups` is required for private ACI networking).
2. If the container group does not need any exposed network endpoint, set `ip_address_type = "None"` instead.
3. Apply NSGs/route tables on the delegated subnet to control east-west traffic to the container group.
4. If external access is genuinely required, front the private container group with an Azure Application Gateway, Front Door, or Azure Firewall/DNAT rule rather than exposing it directly.
5. Note: switching `ip_address_type` from `Public` to `Private` typically forces resource replacement (new container group), so plan for downtime or a blue/green rollout.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureContainerInstancePublicIPAddressType.py)
- [Azure Container Instances virtual network deployment](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-vnet)
