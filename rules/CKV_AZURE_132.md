# CKV_AZURE_132: Ensure cosmosdb does not allow privileged escalation by restricting management plane changes
## Severity
**LOW** (score: 2.0/10)

Leaving key-based metadata write access enabled on CosmosDB lets an attacker with data-plane keys escalate to management-plane changes (e.g. regenerating keys, altering firewall/network rules), a privilege-escalation path around normal RBAC controls.

## Summary
This check ensures that an Azure Cosmos DB account has key-based metadata write access disabled, preventing account keys from being used to modify the account's own management-plane configuration.

## Applicability
- **ARM**: `Microsoft.DocumentDB/databaseAccounts` resources, property `properties/disableKeyBasedMetadataWriteAccess`.
- **Terraform**: `azurerm_cosmosdb_account` resource, attribute `access_key_metadata_writes_enabled`.
- **Bicep**: compiles to the same ARM resource type and property.

## Why it matters
Cosmos DB account (master) keys are typically distributed to application workloads for data-plane read/write access. If key-based metadata write access is left enabled, anyone holding a data-plane account key can also perform management-plane operations — such as modifying the account's own configuration metadata — using nothing more than that key, bypassing Azure RBAC/Azure AD authorization that would normally govern account-level changes. This creates a privilege-escalation path: a credential intended only for reading/writing data can be leveraged to alter account settings, undermining the separation between data-plane and control-plane permissions. Disabling this setting forces management-plane changes to go through Azure AD-authenticated, RBAC-governed paths (e.g., ARM/Portal/CLI with proper role assignments), closing that escalation route.

## How Checkov evaluates this
- **ARM**: Looks at `conf['properties']['disableKeyBasedMetadataWriteAccess']`. PASS only if that property is present and truthy; otherwise (missing `properties`, missing key, or falsy value) it FAILS.
- **Terraform**: A `BaseResourceValueCheck` inspecting `access_key_metadata_writes_enabled` and expecting it to equal `False`. If the attribute is absent, the provider's default (`true`, i.e., enabled) applies and the check FAILS; setting it explicitly to `false` PASSES.

## Non-compliant example
```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                = "example-cosmosdb"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
  # access_key_metadata_writes_enabled left at default (true) — FAILS
}
```

## Remediated example
```hcl
resource "azurerm_cosmosdb_account" "example" {
  name                = "example-cosmosdb"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  access_key_metadata_writes_enabled = false  # blocks key-based metadata writes

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
}
```

## Remediation steps
1. Set `access_key_metadata_writes_enabled = false` on every `azurerm_cosmosdb_account` resource (Terraform), or `disableKeyBasedMetadataWriteAccess: true` under `properties` (ARM/Bicep).
2. Verify no automation, CI/CD pipeline, or application relies on using an account key to change account metadata; migrate any such workflow to Azure AD-authenticated calls with appropriate RBAC roles.
3. Roll this out via Terraform plan/apply or ARM/Bicep redeploy — this is a control-plane setting change and does not require resource replacement or downtime for data operations.
4. Periodically audit Cosmos DB accounts for drift back to the permissive default, since it is `true` (enabled) unless explicitly set.

## References
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CosmosDBDisableAccessKeyWrite.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBDisableAccessKeyWrite.py
- Microsoft docs: https://learn.microsoft.com/en-us/azure/cosmos-db/role-based-access-control
