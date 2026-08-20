# CKV2_AZURE_28: Ensure Container Instance is configured with managed identity
## Severity
**MEDIUM** (score: 5.0/10)

Without a managed identity, container instances typically fall back to embedded credentials or broader shared secrets for accessing other Azure resources, increasing the risk of credential leakage compared to scoped, rotation-free managed identity access.

## Summary
This check verifies that an Azure Container Instance (ACI) container group has a managed identity (`identity.type`) configured, rather than relying on embedded credentials to authenticate to other Azure services.

## Applicability
- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_container_group`

## Why it matters
Containers often need to call other Azure services — Key Vault for secrets, Storage for data, other APIs protected by AAD. Without a managed identity, the only way to authenticate is to embed credentials (client secrets, connection strings, SAS tokens) directly into the container image, environment variables, or command-line arguments. Those credentials are then exposed to anyone who can inspect the container group's configuration, environment, or logs, and they typically have long lifetimes since rotating them requires redeploying the container. A system- or user-assigned managed identity removes this risk entirely: Azure AD issues short-lived tokens transparently, there is no secret to leak, and access can be centrally governed and revoked via RBAC — closing off a very common source of credential leakage in containerized workloads.

## How Checkov evaluates this
This is a **graph-based attribute check** with two conditions ANDed together:
1. `identity.type` must `exist` on the `azurerm_container_group` resource.
2. `identity.type` must have a non-zero "number of words" — i.e., it must actually contain text (not be an empty string), such as `"SystemAssigned"` or `"UserAssigned"`.

If the `identity` block is missing entirely, or present but with an empty `type`, the resource FAILS.

## Non-compliant example
```hcl
resource "azurerm_container_group" "example" {
  name                = "example-containergroup"
  location            = "eastus"
  resource_group_name = "example-rg"
  os_type             = "Linux"

  container {
    name   = "example-app"
    image  = "myregistry.azurecr.io/app:latest"
    cpu    = "1"
    memory = "1.5"

    # Secret baked into an environment variable instead of using a managed identity.
    environment_variables = {
      STORAGE_CONNECTION_STRING = var.storage_connection_string
    }
  }

  # No identity block configured.
}
```

## Remediated example
```hcl
resource "azurerm_container_group" "example" {
  name                = "example-containergroup"
  location            = "eastus"
  resource_group_name = "example-rg"
  os_type             = "Linux"

  # Added: system-assigned managed identity for the container group.
  identity {
    type = "SystemAssigned"
  }

  container {
    name   = "example-app"
    image  = "myregistry.azurecr.io/app:latest"
    cpu    = "1"
    memory = "1.5"
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_container_group` with `type = "SystemAssigned"` (or `"UserAssigned"` with an `identity_ids` list, or `"SystemAssigned, UserAssigned"` for both).
2. Grant the resulting identity the minimum RBAC role needed on the target resources (e.g., `Key Vault Secrets User`, `Storage Blob Data Reader`).
3. Update the containerized application to acquire tokens via the Azure Instance Metadata Service / `DefaultAzureCredential` (or equivalent SDK) instead of reading credentials from environment variables or files.
4. Remove any hardcoded secrets/connection strings from environment variables, command-line args, or the image itself once the managed identity flow is verified working.
5. Note: managed identity support requires the container group to use a supported OS/network configuration; verify compatibility with your specific ACI networking mode if using VNet-integrated container groups.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureContainerInstanceconfigManagedIdentity.json)
- [Managed identity for Azure Container Instances](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity)
