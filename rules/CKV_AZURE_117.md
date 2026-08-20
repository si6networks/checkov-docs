# CKV_AZURE_117: Ensure that AKS uses disk encryption set
## Severity
**LOW** (score: 2.0/10)

Without a customer-managed disk encryption set, node disk data relies on Azure's default platform-managed keys, weakening key-management control over data at rest but not creating a direct network-exploitable path.

## Summary
This check verifies that an Azure Kubernetes Service (AKS) cluster is configured to use a customer-managed Disk Encryption Set for encrypting the OS/data disks of its node pools, rather than relying solely on Azure's default platform-managed encryption keys.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_kubernetes_cluster`

## Why it matters
By default, AKS node disks are encrypted at rest using Microsoft-managed keys, which satisfies baseline encryption requirements but gives the customer no control over key rotation, revocation, or access auditing. For organizations subject to regulatory regimes (HIPAA, PCI-DSS, FedRAMP) or that need to enforce a "customer holds the keys" security posture, encryption keys must be under organizational control (in Azure Key Vault) so that: (1) keys can be rotated or revoked independently of Microsoft's schedule, (2) key usage is auditable via Key Vault logs, and (3) in the event of a legal/compliance need to cryptographically deny data access, the organization — not the cloud provider — controls that lever. Without a Disk Encryption Set, an organization loses this separation of duties and auditability over the cryptographic material protecting node disk contents (which can include cached secrets, container layer data, and ephemeral volume data).

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `disk_encryption_set_id` attribute:
- **PASS** if `disk_encryption_set_id` is set to any non-empty value (the check uses `ANY_VALUE`, meaning it doesn't validate the specific ID, just that one is configured).
- **FAIL** if the attribute is absent (the check explicitly sets `missing_block_result=CheckResult.FAILED`, so an omitted attribute fails rather than passing by default).

## Non-compliant example
```hcl
resource "azurerm_kubernetes_cluster" "example" {
  name                = "aks-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "aksexample"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
  # disk_encryption_set_id not set -> platform-managed keys only
}
```

## Remediated example
```hcl
resource "azurerm_disk_encryption_set" "example" {
  name                = "aks-des-example"
  resource_group_name = azurerm_resource_group.example.name
  location            = "eastus"
  key_vault_key_id    = azurerm_key_vault_key.example.id

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_kubernetes_cluster" "example" {
  name                = "aks-example"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "aksexample"

  disk_encryption_set_id = azurerm_disk_encryption_set.example.id  # customer-managed key encryption

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Create an Azure Key Vault and a key (or reference an existing one) to serve as the customer-managed key.
2. Create an `azurerm_disk_encryption_set` resource referencing that key, and grant its managed identity `get`/`wrapkey`/`unwrapkey` permissions on the Key Vault.
3. Set `disk_encryption_set_id` on the `azurerm_kubernetes_cluster` resource (or, for existing clusters, on the node pool's underlying managed disks — this typically requires setting it at cluster/node-pool creation time and may require replacing the resource).
4. Ensure the Key Vault has soft-delete and purge protection enabled, since deleting the key would render disks unreadable.
5. Set up key rotation policies in Key Vault appropriate to your compliance requirements.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUsesDiskEncryptionSet.py)
- [Azure AKS bring-your-own-keys (BYOK) with disk encryption sets](https://learn.microsoft.com/en-us/azure/aks/azure-disk-customer-managed-keys)
