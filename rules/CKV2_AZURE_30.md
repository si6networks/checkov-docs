# CKV2_AZURE_30: Ensure Azure Container Registry (ACR) has HTTPS enabled for webhook
## Severity
**LOW** (score: 2.0/10)

An ACR webhook configured with a plain HTTP service URI transmits registry event payloads (including image/repo metadata and potentially tokens) in cleartext, exposing them to interception or tampering in transit.

## Summary
This check verifies that an Azure Container Registry webhook's `service_uri` — the endpoint ACR calls when a registry event fires — uses HTTPS rather than plain HTTP.

## Applicability
- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_container_registry_webhook`

## Why it matters
ACR webhooks POST event payloads (image push, delete, quarantine, chart events) to an external endpoint, often including registry metadata and sometimes an authentication token/custom header configured by the operator. If the `service_uri` uses plain HTTP, this payload — and any secret configured in the webhook's custom headers for authenticating the callback — travels in cleartext over the network, making it susceptible to interception or tampering via man-in-the-middle attacks. An attacker who can observe or spoof this traffic could learn about registry activity (reconnaissance for a supply-chain attack) or forge webhook calls to trigger unintended downstream automation (e.g., a CI/CD pipeline that reacts to a forged "image pushed" event).

## How Checkov evaluates this
This is a **graph-based attribute check**:
- The `service_uri` attribute must `starting_with` the string `"https://"`.

Any `service_uri` beginning with `http://` (or any other scheme) causes the resource to FAIL.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = "example-rg"
  location             = "eastus"
  sku                 = "Standard"
}

resource "azurerm_container_registry_webhook" "example" {
  name                = "examplewebhook"
  resource_group_name = "example-rg"
  registry_name       = azurerm_container_registry.example.name
  location            = "eastus"

  service_uri = "http://webhook.internal.example.com/acr-events"
  status      = "enabled"
  scope       = "myrepo:*"
  actions     = ["push"]
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = "example-rg"
  location             = "eastus"
  sku                 = "Standard"
}

resource "azurerm_container_registry_webhook" "example" {
  name                = "examplewebhook"
  resource_group_name = "example-rg"
  registry_name       = azurerm_container_registry.example.name
  location            = "eastus"

  # Fixed: use HTTPS for the webhook callback endpoint.
  service_uri = "https://webhook.internal.example.com/acr-events"
  status      = "enabled"
  scope       = "myrepo:*"
  actions     = ["push"]
}
```

## Remediation steps
1. Update `service_uri` on every `azurerm_container_registry_webhook` to use the `https://` scheme.
2. Ensure the receiving endpoint has a valid TLS certificate (not self-signed, unless the caller/consumer explicitly trusts it) so the HTTPS connection actually succeeds.
3. If the webhook target is an internal service without existing TLS, terminate TLS at a reverse proxy/API gateway in front of it rather than leaving the ACR webhook itself on HTTP.
4. Rotate/set the webhook's custom authentication header (if used) to confirm it's no longer been exposed in cleartext from the prior HTTP configuration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureACR_HTTPSwebhook.json)
- [Azure Container Registry webhooks](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-webhook)
