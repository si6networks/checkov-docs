# CKV2_AZURE_24: Ensure Azure automation account does NOT have overly permissive network access
## Severity
**MEDIUM** (score: 5.0/10)

An Automation account reachable from any public network can be targeted for credential theft or unauthorized runbook execution, giving broad control over connected Azure resources.

## Summary
This check verifies that an Azure Automation Account has its `public_network_access_enabled` attribute explicitly set to `false`, ensuring the account is not reachable over the public internet.

## Applicability
- **IaC framework:** Terraform (graph-based attribute check)
- **Resource type involved:** `azurerm_automation_account`

## Why it matters
Azure Automation Accounts execute runbooks that frequently hold or use privileged credentials, connection strings, and automation logic for managing entire Azure environments (VM management, patching, configuration enforcement). Leaving public network access enabled exposes the account's management and job-execution endpoints to the internet, making it a target for credential-stuffing, DDoS, or exploitation of any authentication weaknesses. Because Automation Accounts often hold "keys to the kingdom" style permissions (they routinely run with Contributor or higher roles across subscriptions to perform their automation tasks), an attacker gaining access via a public endpoint could pivot into broad control over the Azure environment. Restricting network access forces all communication through private endpoints/VNets, dramatically shrinking the attack surface.

## How Checkov evaluates this
This is a **graph-based attribute check**:
- The `azurerm_automation_account` resource's `public_network_access_enabled` attribute must equal `"false"`.

Any other value (unset — which defaults to `true` in the underlying Azure API/provider — or explicitly `true`) causes the resource to FAIL.

## Non-compliant example
```hcl
resource "azurerm_automation_account" "example" {
  name                = "example-automation"
  location            = "eastus"
  resource_group_name = "example-rg"
  sku_name            = "Basic"

  # public_network_access_enabled not set -> defaults to true (publicly reachable)
}
```

## Remediated example
```hcl
resource "azurerm_automation_account" "example" {
  name                = "example-automation"
  location            = "eastus"
  resource_group_name = "example-rg"
  sku_name            = "Basic"

  # Added: explicitly disable public network access.
  public_network_access_enabled = false
}
```

## Remediation steps
1. Set `public_network_access_enabled = false` on every `azurerm_automation_account` resource.
2. Provision a Private Endpoint (`azurerm_private_endpoint`) for the Automation Account so runbook execution, webhooks, and the DSC/Hybrid Worker endpoints remain reachable from within your VNet.
3. Verify any Hybrid Runbook Workers, webhooks, or external callers currently reaching the account over the public endpoint are updated to use the private endpoint's DNS name/IP instead — disabling public access without private connectivity in place will break existing automation.
4. Requires azurerm provider support for `public_network_access_enabled` on `azurerm_automation_account` (available in recent azurerm provider versions) — confirm your provider version supports this attribute.
5. Re-test scheduled runbooks and webhook triggers after the change to confirm connectivity was not disrupted.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/AzureAutomationAccNotOverlyPermissiveNetAccess.json)
- [Azure Automation network isolation using Azure Private Link](https://learn.microsoft.com/en-us/azure/automation/how-to/private-link-security)
