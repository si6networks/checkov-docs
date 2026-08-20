# CKV_AZURE_41: Ensure that the expiration date is set on all secrets

## Severity
**HIGH** (score: 7.5/10)

Secrets lacking an expiration date can be used indefinitely once created, so a leaked or stale secret remains valid far longer than necessary, increasing residual risk without directly exposing it.

## Summary
This check verifies that every Azure Key Vault secret has an expiration date configured, rather than remaining valid indefinitely.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_key_vault_secret`
- **ARM templates**: `Microsoft.KeyVault/vaults/secrets`
- **Bicep**: `Microsoft.KeyVault/vaults/secrets`

## Why it matters
Secrets stored in Key Vault (connection strings, API keys, passwords, tokens) are especially sensitive because they are often directly usable credentials rather than cryptographic key material requiring further computation to exploit. A secret with no expiration date can remain valid forever, so if it leaks — through a misconfigured app setting, a log line, a screenshot, or a compromised CI pipeline — it grants indefinite access to whatever it protects. Forcing an expiration date creates a hard backstop: even if a leaked secret goes unnoticed, its usefulness to an attacker eventually lapses, and the requirement to set an expiry encourages teams to build secret-rotation automation rather than treating vault entries as "set and forget."

## How Checkov evaluates this
- **ARM**: Reads `properties.attributes.exp`. PASSES only if that key exists and its value is truthy (non-zero/non-empty). Otherwise FAILS.
- **Terraform**: Implemented as a generic value check using `ANY_VALUE`; it inspects the top-level `expiration_date` attribute on `azurerm_key_vault_secret`. PASSES if any value is set there.

## Non-compliant example
```hcl
resource "azurerm_key_vault_secret" "example" {
  name         = "db-connection-string"
  value        = var.db_connection_string
  key_vault_id = azurerm_key_vault.example.id
}
```

## Remediated example
```hcl
resource "azurerm_key_vault_secret" "example" {
  name            = "db-connection-string"
  value           = var.db_connection_string
  key_vault_id    = azurerm_key_vault.example.id
  expiration_date = "2027-08-19T00:00:00Z"
}
```

## Remediation steps
1. Add `expiration_date` (Terraform, RFC3339 timestamp) to every `azurerm_key_vault_secret` resource, or set `properties.attributes.exp` in ARM/Bicep templates.
2. Align the expiry window with the actual credential's own rotation cadence (e.g., match a database password's rotation schedule, or a shorter window for high-value API tokens).
3. Build automation (Azure Automation, Logic Apps, or an application-level rotation job) to regenerate the underlying secret and update the Key Vault entry with a new value and extended expiration before the old one lapses — an expired secret with no rotation plan causes an outage.
4. Alert on secrets approaching expiration (Key Vault emits `SecretNearExpiry` events that can be routed to Event Grid) so teams have lead time.
5. Audit existing secrets lacking an expiration date and retrofit them in a controlled manner to avoid breaking dependent applications.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SecretExpirationDate.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecretExpirationDate.py)
- [Azure Key Vault secrets overview](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets)
