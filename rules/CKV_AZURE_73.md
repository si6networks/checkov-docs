# CKV_AZURE_73: Ensure that Automation account variables are encrypted

## Severity
**LOW** (score: 2.0/10)

Unencrypted Automation account variables can expose configuration data (potentially including sensitive values) at rest, though access still requires prior control-plane permissions.

## Summary
This check ensures Azure Automation Account variable assets (bool, string, int, datetime) are stored with encryption enabled rather than in plaintext.

## Applicability
- **Terraform**: `azurerm_automation_variable_bool`, `azurerm_automation_variable_datetime`, `azurerm_automation_variable_int`, `azurerm_automation_variable_string`
- **ARM/Bicep**: `Microsoft.Automation/automationAccounts/variables`

## Why it matters
Automation Account variables are frequently used to hold configuration values referenced by runbooks — and in practice this often includes sensitive data such as connection strings, API keys, or credentials, even though a dedicated "credential" asset type exists. If a variable is not marked encrypted, its value is stored and displayed in plaintext within the Automation Account, visible to anyone with read access to the account (e.g. via the Portal, CLI, or REST API), and it also appears unencrypted in Automation Account audit logs and job history. Encrypting the variable ensures Azure stores and retrieves the value using envelope encryption tied to the Automation Account, reducing exposure from over-broad read permissions or log/export leakage.

## How Checkov evaluates this
`BaseResourceValueCheck` inspects the `encrypted` attribute (Terraform) or `properties/isEncrypted` (ARM) and expects it to be `true`. Any variable resource lacking this flag or with it set to `false` fails.

## Non-compliant example
```hcl
resource "azurerm_automation_variable_string" "example" {
  name                    = "db-connection-string"
  resource_group_name     = azurerm_resource_group.example.name
  automation_account_name = azurerm_automation_account.example.name
  value                   = "Server=tcp:...;Password=P@ssw0rd;"
  # encrypted omitted -> defaults to false, stored in plaintext
}
```

## Remediated example
```hcl
resource "azurerm_automation_variable_string" "example" {
  name                    = "db-connection-string"
  resource_group_name     = azurerm_resource_group.example.name
  automation_account_name = azurerm_automation_account.example.name
  value                   = "Server=tcp:...;Password=P@ssw0rd;"
  encrypted               = true   # variable is now encrypted at rest
}
```

## Remediation steps
1. Add `encrypted = true` to every `azurerm_automation_variable_*` resource.
2. Be aware that `encrypted` is set at creation time — changing it on an existing variable typically forces resource replacement in the `azurerm` provider, so plan for the variable to be recreated (and its value re-populated).
3. For genuinely secret values, prefer an Automation Credential asset or store the secret in Key Vault and reference it from the runbook, rather than relying solely on an encrypted variable.
4. Audit existing Automation Accounts for any string/int/datetime/bool variables holding secrets and rotate those secrets after migrating to encrypted storage.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AutomationEncrypted.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AutomationEncrypted.py
- Azure docs: https://learn.microsoft.com/en-us/azure/automation/shared-resources/variables
