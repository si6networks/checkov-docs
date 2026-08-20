# CKV2_AZURE_36: Ensure Azure automation account is configured with managed identity
## Severity
**LOW** (score: 2.0/10)

Without a managed identity, the Automation account depends on embedded or shared credentials to authenticate to other Azure resources, increasing the risk of credential leakage versus scoped identity-based access.

## Summary
This check verifies that an Azure Automation Account has a managed identity configured, rather than relying solely on the legacy "Run As" account or embedded credentials for its runbook authentication.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_automation_account`

## Why it matters
Automation Account runbooks frequently need to authenticate to Azure to perform management tasks — starting/stopping VMs, rotating keys, applying configuration. Historically this was done via the "Run As" account mechanism, which relies on a self-signed certificate stored as an Automation credential asset; that certificate has a fixed expiry, requires manual renewal, and if exported or leaked grants whatever permissions the Run As service principal holds. Microsoft has deprecated Run As accounts in favor of managed identities specifically because of these operational and security weaknesses. A managed identity removes the certificate-management burden entirely, has no exportable secret, and lets Azure AD issue short-lived tokens transparently — closing off a credential-leakage vector that runbooks (which often already carry significant privileges) are a highly attractive target for.

## How Checkov evaluates this
This is a **graph-based attribute check** with two ANDed conditions:
1. `identity.type` must `exist` on the `azurerm_automation_account` resource.
2. `identity.type` must have a non-zero "number of words" (i.e., must not be an empty string).

If the `identity` block is missing, or present but with an empty `type`, the resource FAILS.

## Non-compliant example
```hcl
resource "azurerm_automation_account" "example" {
  name                = "example-automation"
  location            = "eastus"
  resource_group_name = "example-rg"
  sku_name            = "Basic"

  # No identity block — runbooks likely rely on a legacy Run As account
  # or embedded credentials instead of a managed identity.
}
```

## Remediated example
```hcl
resource "azurerm_automation_account" "example" {
  name                = "example-automation"
  location            = "eastus"
  resource_group_name = "example-rg"
  sku_name            = "Basic"

  # Added: system-assigned managed identity for runbook authentication.
  identity {
    type = "SystemAssigned"
  }
}
```

## Remediation steps
1. Add an `identity` block to the `azurerm_automation_account` resource, with `type = "SystemAssigned"` (or a user-assigned identity for shared-identity scenarios across multiple automation accounts).
2. Grant the resulting identity the specific RBAC roles it needs on target resources (e.g., `Virtual Machine Contributor` scoped to the relevant resource group, not subscription-wide `Contributor`).
3. Update existing runbooks to authenticate using `Connect-AzAccount -Identity` (PowerShell) or the equivalent Python SDK managed-identity credential, replacing any `Get-AutomationConnection -Name "AzureRunAsConnection"` calls.
4. If migrating from a legacy Run As account, follow Microsoft's migration guidance and plan to decommission the Run As service principal/certificate once all runbooks are confirmed working on the managed identity — Run As accounts have been deprecated and their certificates will eventually expire without renewal options.
5. Test all scheduled/webhook-triggered runbooks after the change, since authentication code paths differ between Run As and managed identity.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureAutomationAccConfigManagedIdentity.json)
- [Automation account managed identities](https://learn.microsoft.com/en-us/azure/automation/automation-security-overview#managed-identities)
