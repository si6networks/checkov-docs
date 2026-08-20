# CKV_AZURE_126: Ensures that Active Directory is used for authentication for Service Fabric
## Severity
**LOW** (score: 2.0/10)

Without Azure AD-backed authentication, Service Fabric cluster management relies on weaker certificate-only authentication, increasing the risk of unauthorized administrative access to the cluster.

## Summary
This check verifies that an Azure Service Fabric cluster is configured to use Azure Active Directory for client authentication, rather than relying solely on certificate-based client authentication.

## Applicability
- **IaC framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_service_fabric_cluster`

## Why it matters
Service Fabric clusters can authenticate management-plane clients (e.g. anyone using Service Fabric Explorer or the client SDK to manage the cluster) using either client certificates or Azure Active Directory. Certificate-only authentication has real operational weaknesses: certificates must be manually distributed, tracked, and revoked out-of-band, there's no natural integration with centralized identity governance (MFA, conditional access, group-based RBAC, access reviews), and a leaked or stolen certificate grants access until someone notices and manually revokes it. Azure AD integration instead lets the organization apply its existing identity controls — MFA, conditional access policies, just-in-time access, and centralized offboarding — directly to cluster management access, and provides an auditable, centrally revocable identity trail (via Azure AD sign-in logs) instead of opaque certificate thumbprints. Without AD integration, cluster management access control tends to degrade over time as certificates are shared or forgotten about long after an employee's departure.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `azure_active_directory[0].tenant_id` attribute:
- **PASS** if an `azure_active_directory` block is present and its `tenant_id` is set to any non-empty value (`ANY_VALUE`).
- **FAIL** if the `azure_active_directory` block or its `tenant_id` is absent.

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

  # no azure_active_directory block -> certificate-only authentication

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

  azure_active_directory {
    tenant_id             = data.azurerm_client_config.current.tenant_id
    cluster_application_id = azuread_application.cluster.application_id
    client_application_id  = azuread_application.client.application_id
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
1. Register two Azure AD applications: a "cluster" app (representing the Service Fabric cluster resource) and a "client" app (representing management tool clients like Service Fabric Explorer).
2. Add an `azure_active_directory` block to the `azurerm_service_fabric_cluster` resource with `tenant_id`, `cluster_application_id`, and `client_application_id` populated from those registrations.
3. Assign appropriate Azure AD users/groups to admin vs. read-only roles in the client application's app roles, so RBAC can be enforced through Azure AD group membership.
4. This can typically be added to an existing cluster without recreating it, but coordinate with cluster administrators since it changes how they authenticate to management tools going forward.
5. Consider retaining certificate-based authentication as a secondary/emergency access method rather than removing it entirely, per Microsoft's guidance.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ActiveDirectoryUsedAuthenticationServiceFabric.py)
- [Azure Service Fabric Azure AD client authentication documentation](https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-security-roles)
