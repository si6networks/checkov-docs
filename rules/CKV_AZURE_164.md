# CKV_AZURE_164: Ensures that ACR uses signed/trusted images

## Severity
**MEDIUM** (score: 5.0/10)

Unsigned/untrusted images allow tampered or malicious container images to be pulled and deployed to production without verifying provenance, opening a supply-chain path to running attacker-controlled code.

## Summary
This check ensures that an Azure Container Registry (ACR) has content trust (Docker Notary-based image signing) enabled, so only signed/trusted images can be pushed and pulled.

## Applicability
- **Terraform**: `azurerm_container_registry` resource.

## Why it matters
Without content trust enforcement, an ACR will accept and serve any image regardless of whether it was signed by a trusted publisher. This opens the door to supply-chain attacks: a compromised CI pipeline, a leaked registry credential, or an insider could push a tampered or malicious image, and downstream deployments (AKS, App Service, ACI, etc.) would pull and run it with no verification that the image's content matches what was originally built and approved. Enabling trust policy/content trust ensures every image is cryptographically signed and that signature is verified before pull, closing off a common tampering vector between "build" and "deploy."

## How Checkov evaluates this
The check (`ACRUseSignedImages`) inspects the `azurerm_container_registry` resource configuration for either:
- a top-level `trust_policy_enabled` attribute equal to `true`, or
- a `trust_policy` block whose `enabled` attribute is `true`.

If either condition is met, the check **PASSES**. If neither is present/true, it **FAILS**. Note that in the Azure Terraform provider, the `trust_policy` block (and content trust) is only supported/effective on Premium SKU registries.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"
  admin_enabled       = false
  # No trust_policy block -> content trust disabled
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"
  admin_enabled       = false

  trust_policy {
    enabled = true
  }
}
```

## Remediation steps
1. Ensure the ACR SKU is `Premium` — content trust/trust policy requires Premium tier.
2. Add a `trust_policy { enabled = true }` block to the `azurerm_container_registry` resource (or set `trust_policy_enabled = true` on provider versions that expose it as a top-level attribute).
3. Sign images at build/push time using Docker Content Trust / Notary tooling (`docker trust sign`) integrated into your CI pipeline, since enabling the policy alone does not retroactively sign existing images.
4. Re-test pulls in downstream consumers (AKS, App Service) after enabling, since unsigned images will be rejected once trust is enforced.
5. Note this is a paid-tier feature; budget for the Premium SKU cost increase if migrating from Basic/Standard.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRUseSignedImages.py
