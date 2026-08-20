# CKV2_AZURE_11: Ensure that Azure Data Explorer encryption at rest uses a customer-managed key

## Severity
**LOW** (score: 2.0/10)

Data Explorer clusters are encrypted at rest by default; omitting a customer-managed key reduces control over key lifecycle and revocation rather than leaving data unencrypted.

## Summary
This check ensures that an Azure Data Explorer (Kusto) cluster has a customer-managed key configured for encryption at rest, instead of relying on Microsoft-managed keys.

## Applicability
- **IaC framework:** Terraform (graph-based check).
- **Resource types:** `azurerm_kusto_cluster`, connected via `azurerm_kusto_cluster_customer_managed_key`.

## Why it matters
Azure Data Explorer clusters often store large volumes of telemetry, log, and analytics data — sometimes including sensitive operational or security data. Without a customer-managed key, encryption keys are entirely controlled by Microsoft, meaning the organization cannot independently revoke access, enforce its own rotation cadence, or demonstrate exclusive key custody for regulatory/compliance purposes. If a cluster is later found to contain data subject to strict data-residency or key-control requirements (e.g. government, financial, or healthcare workloads), lacking CMK support means the only remediation is a costly data migration to a newly configured cluster — CMK cannot always be added retroactively without cluster recreation, making this a "get it right at creation" concern.

## How Checkov evaluates this
Graph check (`DataExplorerEncryptionUsesCustomKey.json`). PASS requires:
1. Filter to `azurerm_kusto_cluster` resources.
2. The cluster must have a **connection** to an `azurerm_kusto_cluster_customer_managed_key` resource.

FAIL if the Kusto cluster has no linked `azurerm_kusto_cluster_customer_managed_key` resource.

## Non-compliant example
```hcl
resource "azurerm_kusto_cluster" "adx" {
  name                = "analyticscluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  sku {
    name     = "Standard_D13_v2"
    capacity = 2
  }
  # No azurerm_kusto_cluster_customer_managed_key -> fails
}
```

## Remediated example
```hcl
resource "azurerm_kusto_cluster" "adx" {
  name                = "analyticscluster"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  sku {
    name     = "Standard_D13_v2"
    capacity = 2
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_key_vault_key" "adx_key" {
  name         = "adx-cmk"
  key_vault_id = azurerm_key_vault.kv.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_kusto_cluster_customer_managed_key" "adx_cmk" {
  cluster_id   = azurerm_kusto_cluster.adx.id
  key_vault_id = azurerm_key_vault.kv.id
  key_name     = azurerm_key_vault_key.adx_key.name
}
```

## Remediation steps
1. Enable a `SystemAssigned` (or `UserAssigned`) managed identity on the Kusto cluster.
2. Grant the identity `Get`, `WrapKey`, and `UnwrapKey` permissions on the target Key Vault key (via access policy or the `Key Vault Crypto Service Encryption User` RBAC role).
3. Add an `azurerm_kusto_cluster_customer_managed_key` resource referencing the cluster and the Key Vault key.
4. Enable soft-delete and purge protection on the Key Vault — Azure requires this for CMK integrations across most services, including Kusto.
5. Adding CMK to an existing cluster may be supported in-place depending on `azurerm` provider/API version — verify against current AzureRM provider docs, as some Kusto encryption settings historically required cluster recreation; test in a non-production environment first.
6. Establish a key rotation and monitoring plan — if the Key Vault key becomes inaccessible (deleted, disabled, or access revoked), the cluster can lose the ability to decrypt data.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/DataExplorerEncryptionUsesCustomKey.json)
- [Azure: Configure customer-managed keys for encryption in Azure Data Explorer](https://learn.microsoft.com/en-us/azure/data-explorer/security-network-security)
