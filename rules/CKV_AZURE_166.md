# CKV_AZURE_166: Ensure container image quarantine, scan, and mark images verified

## Severity
**MEDIUM** (score: 5.0/10)

Without image quarantine, newly pushed images are immediately pullable before malware/vulnerability scanning completes, letting a compromised or vulnerable image reach production via automated CI/CD before it is vetted.

## Summary
This check ensures that images pushed to an Azure Container Registry are held in quarantine and scanned before being marked verified and made generally pullable.

## Applicability
- **Terraform**: `azurerm_container_registry` resource (`quarantine_policy_enabled`).
- **ARM/Bicep**: `Microsoft.ContainerRegistry/registries` resource (`properties.policies.quarantinePolicy.status` = `"enabled"`).

## Why it matters
Without a quarantine policy, an image pushed to the registry is immediately available for pull by any consumer, including automated deployment pipelines and AKS nodes, before it has been vetted for known vulnerabilities or malware. A quarantine policy holds newly pushed images in an isolated state until a scanning solution (e.g., Microsoft Defender for Cloud's container image scanning or a third-party scanner integrated via webhook) inspects them and marks them verified. This closes the window in which a vulnerable or malicious image could be automatically deployed by a fast CI/CD pipeline before a human or automated scan has a chance to flag it — a meaningful supply-chain control, especially in environments with continuous deployment.

## How Checkov evaluates this
- **Terraform**: `ACREnableImageQuarantine` is a `BaseResourceValueCheck` that inspects the `quarantine_policy_enabled` attribute on `azurerm_container_registry`. If it is set to `true`, the check **PASSES**; otherwise it **FAILS**.
- **ARM**: `ACREnableImageQuarantine` inspects `properties.policies.quarantinePolicy.status` on `Microsoft.ContainerRegistry/registries` and expects the value `"enabled"`; any other value (or absence) **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"
  # quarantine_policy_enabled not set (defaults to disabled)
}
```

```json
{
  "type": "Microsoft.ContainerRegistry/registries",
  "apiVersion": "2019-05-01",
  "name": "myregistry",
  "properties": {
    "policies": {}
  }
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "acr" {
  name                    = "myregistry"
  resource_group_name     = azurerm_resource_group.rg.name
  location                = azurerm_resource_group.rg.location
  sku                     = "Premium"
  quarantine_policy_enabled = true
}
```

```json
{
  "type": "Microsoft.ContainerRegistry/registries",
  "apiVersion": "2019-05-01",
  "name": "myregistry",
  "properties": {
    "policies": {
      "quarantinePolicy": {
        "status": "enabled"
      }
    }
  }
}
```

## Remediation steps
1. Set `quarantine_policy_enabled = true` on the `azurerm_container_registry` resource (Terraform), or `properties.policies.quarantinePolicy.status = "enabled"` (ARM/Bicep).
2. This feature requires the Premium ACR SKU.
3. Wire up an actual scanning solution (Microsoft Defender for Containers, or a custom webhook) that inspects quarantined images and promotes them to verified — enabling the flag alone holds images in quarantine but does nothing without a scanner acting on them.
4. Update CI/CD pipelines to tolerate the quarantine delay before an image becomes pullable, to avoid deployment failures immediately after push.
5. Note this is a preview/legacy ACR feature area; verify current Azure documentation for continued support before relying on it long-term.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACREnableImageQuarantine.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/ACREnableImageQuarantine.py
