# CKV_AZURE_138: Ensures that ACR disables anonymous pulling of images
## Severity
**LOW** (score: 2.0/10)

Allowing anonymous pulls on Standard/Premium ACR SKUs exposes container images (which frequently embed application code, dependency manifests, or accidentally-baked secrets) to unauthenticated public access.

## Summary
This check ensures an Azure Container Registry on the Standard or Premium SKU does not allow anonymous (unauthenticated) pulling of images.

## Applicability
- **ARM**: `Microsoft.ContainerRegistry/registries` resources, properties `properties/anonymousPullEnabled` and `sku`.
- **Terraform**: `azurerm_container_registry` resource, attributes `anonymous_pull_enabled` and `sku`.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
Anonymous pull access lets anyone on the internet who knows (or discovers/enumerates) the registry name and repository/tag pull container images without any authentication at all. This can expose proprietary application code baked into image layers (source code, build artifacts, internal tooling), configuration files and environment defaults embedded in images, and potentially secrets accidentally committed to a layer during a build. It also reveals your internal software inventory and versioning to attackers, aiding reconnaissance for known-CVE targeting of the exact versions in use. Anonymous pull is only meaningful/available on Standard and Premium SKUs (Basic doesn't support it); the check specifically targets those tiers since that's where the exposure is possible.

## How Checkov evaluates this
The check reads `anonymousPullEnabled` (ARM: `properties.anonymousPullEnabled`; Terraform: `anonymous_pull_enabled`) and the registry `sku`. It FAILS only when **all** of the following are true simultaneously: the `sku` name is `Standard` or `Premium`, AND `anonymousPullEnabled`/`anonymous_pull_enabled` is truthy. If the SKU is `Basic` (where the feature doesn't apply), or if anonymous pull is not enabled, the check PASSES.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "example" {
  name                   = "exampleacr"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  sku                    = "Standard"
  anonymous_pull_enabled = true  # FAILS -- unauthenticated pulls allowed on Standard SKU
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "example" {
  name                   = "exampleacr"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  sku                    = "Standard"
  anonymous_pull_enabled = false  # requires authentication for every pull
}
```

## Remediation steps
1. Set `anonymous_pull_enabled = false` (Terraform) or `properties.anonymousPullEnabled: false` (ARM/Bicep), or omit it entirely since the default is disabled.
2. If anonymous pull was enabled to support a specific public-distribution use case (e.g. publishing an open-source base image), consider a dedicated, separate registry scoped only to that purpose rather than enabling it on a registry that also holds private images.
3. Audit existing images in the registry for any that may have already been pulled anonymously while the setting was enabled, and rotate any secrets that may have been embedded in those layers.
4. Require authenticated access (Azure AD / `AcrPull` role, or repository-scoped tokens) for all internal and CI/CD consumers going forward.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/ACRAnonymousPullDisabled.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAnonymousPullDisabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/container-registry/anonymous-pull-access
