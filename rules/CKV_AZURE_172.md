# CKV_AZURE_172: Ensure autorotation of Secrets Store CSI Driver secrets for AKS clusters

## Severity
**MEDIUM** (score: 5.0/10)

Without autorotation, secrets synced from Key Vault into the cluster via the CSI driver can go stale after a credential rotation or revocation, extending the window an already-compromised or intentionally revoked secret remains usable inside the cluster.

## Summary
This check ensures that AKS clusters using the Azure Key Vault Secrets Provider (Secrets Store CSI Driver add-on) have automatic secret rotation enabled, so secrets mounted into pods stay in sync with the source Key Vault.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_kubernetes_cluster` (`key_vault_secrets_provider.secret_rotation_enabled`).
- **ARM/Bicep**: `Microsoft.ContainerService/managedClusters` (`properties.addonProfiles.azureKeyvaultSecretsProvider.config.enableSecretRotation`).

## Why it matters
The Secrets Store CSI Driver mounts secrets (credentials, connection strings, certificates) from Key Vault into pods as files, typically at pod start. Without rotation, a secret that is rotated in Key Vault — for example after a suspected compromise, or as part of routine credential hygiene — will continue to be used by already-running pods in its old, stale form until the pod restarts for an unrelated reason. This directly undermines incident response: an operator who rotates a leaked credential in Key Vault, believing it invalidates the exposure, may find that running workloads keep using the old value indefinitely. Enabling autorotation ensures the CSI driver periodically re-syncs mounted secrets from Key Vault, so credential rotation actually takes effect across the cluster within a bounded time window.

## How Checkov evaluates this
- **Terraform** (`AkSSecretStoreRotation`, a `BaseResourceValueCheck`): inspects `key_vault_secrets_provider/secret_rotation_enabled`. If `true`, **PASSES**; otherwise **FAILS**.
- **ARM**: inspects `properties/addonProfiles/azureKeyvaultSecretsProvider/config/enableSecretRotation` and expects a truthy value; missing or `false` **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"

  key_vault_secrets_provider {
    # secret_rotation_enabled not set -> defaults to false
  }

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediated example
```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAksCluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_prefix          = "myaks"

  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Add a `key_vault_secrets_provider` block with `secret_rotation_enabled = true` to the `azurerm_kubernetes_cluster` resource.
2. Optionally set `secret_rotation_interval` (default is typically 2 minutes) to tune polling frequency against Key Vault API rate limits.
3. Ensure the `SecretProviderClass` objects deployed in the cluster reference the correct Key Vault objects/versions and that workload identities have `get`/`list` permissions on those secrets.
4. Note that rotation updates the mounted file content, but applications that cache secret values in memory at startup will still need to be restarted or designed to re-read the file periodically to benefit from rotation.
5. Requires the Azure Key Vault Provider for Secrets Store CSI Driver add-on to be enabled in the first place.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSSecretStoreRotation.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AkSSecretStoreRotation.py
- Microsoft Docs: https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver
