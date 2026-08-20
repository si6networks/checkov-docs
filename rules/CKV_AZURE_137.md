# CKV_AZURE_137: Ensure ACR admin account is disabled
## Severity
**LOW** (score: 2.0/10)

The ACR admin account is a single shared, non-AAD credential that bypasses per-user RBAC and audit trails for pushing/pulling images, so leaving it enabled creates a persistent, hard-to-monitor privileged access path into the registry.

## Summary
This check ensures the admin user account is disabled on an Azure Container Registry (ACR), forcing image push/pull authentication to go through Azure AD identities/RBAC instead of a shared, static admin credential.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **ARM**: `Microsoft.ContainerRegistry/registries` resources, property `properties/adminUserEnabled`.
- **Terraform**: `azurerm_container_registry` resource, attribute `admin_enabled`.
- **Bicep**: compiles to the same ARM resource type.

## Why it matters
The ACR admin account is a single shared username/password credential with full push/pull rights to the entire registry, independent of Azure AD identity. It cannot be scoped to individual users, cannot enforce MFA, cannot be tied to conditional access policies, and grants no audit trail of *which person* used it — every action is attributed to the same generic admin identity. If this credential is embedded in a CI/CD pipeline, a Dockerfile, a script, or leaks via a misconfigured secret store, an attacker gains full read/write access to every image in the registry: they can pull proprietary images (IP theft, source-in-layers exposure) or push a tampered/backdoored image that gets pulled and deployed downstream by anything trusting that registry — a supply-chain compromise. Azure AD-based (RBAC) authentication instead allows per-identity, revocable, auditable, least-privilege access (e.g., `AcrPull` vs `AcrPush` roles scoped to specific service principals/managed identities).

## How Checkov evaluates this
Both variants are `BaseResourceNegativeValueCheck`s that treat `True` as a forbidden value:
- **ARM**: inspects `properties/adminUserEnabled`; FAILS if it equals `True`.
- **Terraform**: inspects `admin_enabled`; FAILS if it equals `True`.
If the attribute is absent, the provider default (`false`, disabled) applies, so the check PASSES by default — only an explicit `true` triggers a failure.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard"
  admin_enabled        = true  # FAILS -- shared static admin credential enabled
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard"
  admin_enabled        = false  # forces Azure AD-based authentication
}
```

## Remediation steps
1. Set `admin_enabled = false` (Terraform) or `properties.adminUserEnabled: false` (ARM/Bicep), or simply omit the attribute since the default is already disabled.
2. Migrate any pipelines/scripts currently using the admin username/password to Azure AD authentication — e.g. `az acr login` with a managed identity or service principal, or `AcrPull`/`AcrPush` role assignments on the registry.
3. If admin credentials were previously enabled and possibly distributed, rotate/regenerate them (`az acr credential renew`) even after disabling the account, since disabling can typically be re-enabled, and any leaked credential should be treated as compromised.
4. Verify Kubernetes/AKS workloads pulling from this ACR use `az aks update --attach-acr` (managed identity-based) integration rather than embedded admin credentials in image pull secrets.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/ACRAdminAccountDisabled.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAdminAccountDisabled.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication
