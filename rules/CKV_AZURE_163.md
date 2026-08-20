# CKV_AZURE_163: Enable vulnerability scanning for container images

## Severity
**MEDIUM** (score: 5.0/10)

Without vulnerability scanning enabled, a container registry can distribute images with known, exploitable vulnerabilities into production without detection, undermining the ability to catch supply-chain risk before deployment.

## Summary
This check ensures that an Azure Container Registry (ACR) is provisioned on a SKU tier (Standard or Premium) that supports Microsoft Defender for Cloud's container image vulnerability scanning, rather than the Basic tier which does not support it.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM
- **Resource types:**
  - Terraform: `azurerm_container_registry`
  - ARM/Bicep: `Microsoft.ContainerRegistry/registries`

## Why it matters
Container images frequently bundle third-party OS packages and libraries that accumulate known CVEs over time. Without vulnerability scanning, a registry can silently host and distribute images containing critical, exploitable vulnerabilities (e.g., a vulnerable base image or an outdated dependency with a remote code execution flaw) into production without any automated detection. Since Defender for Cloud's registry scanning capability (and equivalent scanning integrations) are only available on the Standard/Premium ACR tiers, choosing the Basic tier effectively forecloses this control at the infrastructure level — no configuration on top of a Basic registry can enable image scanning. This check flags that structural gap early, at the IaC stage, rather than after a vulnerable image has already been deployed.

## How Checkov evaluates this
Both the Terraform and ARM/Bicep versions of this check look at the registry's `sku`:
- **Terraform:** inspects `sku` (a string attribute) on `azurerm_container_registry`. **PASS** if `sku` equals `"Standard"` or `"Premium"`. **FAIL** otherwise (including `"Basic"` or missing).
- **ARM/Bicep:** inspects `sku.name`. **PASS** if `sku.name` equals `"Standard"` or `"Premium"`. **FAIL** otherwise.

Note this check only validates the SKU tier is scan-capable — it does not itself verify that a Defender for Cloud vulnerability scanning plan is actually enabled and configured against the registry; that is a separate Azure/Defender-side configuration.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Basic"   # Basic tier does not support vulnerability scanning
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard"   # supports Defender for Cloud vulnerability scanning
}
```

## Remediation steps
1. Set `sku = "Standard"` or `sku = "Premium"` (Terraform) — or `sku.name` equivalently in ARM/Bicep — on the container registry.
2. Changing the SKU tier is generally an in-place upgrade in Azure (Basic → Standard → Premium), but confirm with `terraform plan` for your provider version, as some SKU transitions may show as requiring replacement.
3. After upgrading the SKU, separately enable Microsoft Defender for Cloud's "Defender for Container Registries" (or the newer "Defender for Containers") plan on the subscription/registry so images are actually scanned — the SKU alone only makes scanning *possible*, not active.
4. Consider Premium if you also need features like geo-replication, private endpoints, or higher throughput/storage limits, in addition to scanning support.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRContainerScanEnabled.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/ACRContainerScanEnabled.py)
- [Microsoft Defender for Containers documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
