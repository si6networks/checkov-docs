# CKV_AZURE_125: Ensures that Service Fabric use three levels of protection available
## Severity
**LOW** (score: 2.0/10)

Weak Service Fabric protection levels (below EncryptAndSign) allow cluster node-to-node and client-to-node traffic to be read or tampered with, undermining the integrity and confidentiality of cluster management traffic.

## Summary
This check verifies that an Azure Service Fabric cluster's security setting is configured to `EncryptAndSign`, the strongest of Service Fabric's cluster protection levels, ensuring node-to-node communication is both encrypted and integrity-signed.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** Terraform, ARM templates, Bicep
- **Resource types:**
  - Terraform: `azurerm_service_fabric_cluster`
  - ARM: `Microsoft.ServiceFabric/clusters`

## Why it matters
Service Fabric clusters coordinate cluster-management and application traffic between nodes over the network, and the `ClusterProtectionLevel` setting determines how that inter-node traffic is protected. Service Fabric supports three levels: `None` (no protection — traffic is plaintext and unauthenticated between nodes), `Sign` (traffic is signed for integrity but not encrypted, so it can be read but not tampered with undetected), and `EncryptAndSign` (traffic is both encrypted and signed). Running below `EncryptAndSign` means an attacker with network access to the cluster's VNet (e.g. via a compromised VM on the same subnet, or a misconfigured peering) can eavesdrop on management-plane and application traffic between Service Fabric nodes, or in the `None` case, potentially inject or tamper with traffic since neither confidentiality nor integrity is guaranteed. Given that Service Fabric often hosts multi-tenant or business-critical microservices, weak protection on the inter-node fabric channel is a significant lateral-movement and data-exposure risk.

## How Checkov evaluates this
Both implementations look inside the cluster's `fabricSettings`/`fabric_settings` collection for an entry whose `name` is `"Security"`, and within that entry's `parameters`, for a parameter named `ClusterProtectionLevel`:
- **PASS** if such a setting exists and its `value` equals exactly `"EncryptAndSign"`.
- **FAIL** in every other case: no `Security` setting present, a `ClusterProtectionLevel` parameter with any other value (`"None"` or `"Sign"`), or malformed/missing `parameters` structure.

## Non-compliant example
```hcl
resource "azurerm_service_fabric_cluster" "example" {
  name                = "sf-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"
  reliability_level    = "Bronze"
  upgrade_mode         = "Automatic"
  vm_image             = "Windows"
  management_endpoint  = "https://example:19080"

  fabric_settings {
    name = "Security"
    parameters = {
      "ClusterProtectionLevel" = "Sign"  # signed but not encrypted
    }
  }

  node_type {
    name                 = "primary"
    instance_count       = 3
    is_primary           = true
    client_endpoint_port = 19000
    http_endpoint_port   = 19080
  }
}
```

## Remediated example
```hcl
resource "azurerm_service_fabric_cluster" "example" {
  name                = "sf-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"
  reliability_level    = "Bronze"
  upgrade_mode         = "Automatic"
  vm_image             = "Windows"
  management_endpoint  = "https://example:19080"

  fabric_settings {
    name = "Security"
    parameters = {
      "ClusterProtectionLevel" = "EncryptAndSign"  # encrypted and signed inter-node traffic
    }
  }

  node_type {
    name                 = "primary"
    instance_count       = 3
    is_primary           = true
    client_endpoint_port = 19000
    http_endpoint_port   = 19080
  }
}
```

## Remediation steps
1. Add a `fabric_settings` block (Terraform) or `fabricSettings` array entry (ARM) with `name = "Security"`.
2. Within its `parameters`, set `ClusterProtectionLevel` to `"EncryptAndSign"`.
3. Note that changing the cluster protection level on an existing, running cluster is a sensitive operation — Microsoft's guidance requires progressing through levels in order (`None` → `Sign` → `EncryptAndSign`), not jumping directly, and typically requires the cluster's management certificate to already be properly configured before `EncryptAndSign` can be applied.
4. Ensure the cluster has a valid management certificate configured, since `EncryptAndSign` depends on certificate-based node identity for the encryption/signing to function.
5. Plan for a maintenance window — protection level changes trigger a rolling upgrade across cluster nodes.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServiceFabricClusterProtectionLevel.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureServiceFabricClusterProtectionLevel.py)
- [Azure Service Fabric cluster security documentation](https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-security)
