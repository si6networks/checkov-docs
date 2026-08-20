# CKV_AZURE_40: Ensure that the expiration date is set on all keys

## Severity
**HIGH** (score: 7.5/10)

Key Vault keys without an expiration date can remain valid indefinitely, weakening cryptographic hygiene and increasing the blast radius if a key is ever compromised, though this alone does not expose the key.

## Summary
This check verifies that every Azure Key Vault key resource has an expiration date configured, rather than being valid indefinitely.

## Applicability
- **Terraform**: `azurerm_key_vault_key`
- **ARM templates**: `Microsoft.KeyVault/vaults/keys`
- **Bicep**: `Microsoft.KeyVault/vaults/keys`

## Why it matters
Cryptographic keys that never expire violate the principle of key rotation, a fundamental cryptographic hygiene practice. A key with no expiration date can remain in active use indefinitely, meaning that if it is ever compromised (exfiltrated, leaked in logs, or exposed through an application vulnerability), the exposure window is unbounded — the same key material continues protecting data forever unless someone remembers to manually rotate it. Mandating an expiration date forces a periodic rotation cadence, limits the blast radius of any single key compromise, and satisfies common compliance mandates (PCI-DSS, NIST 800-57) around cryptoperiod limits for keys used in encryption/signing operations.

## How Checkov evaluates this
This is implemented as a generic "value check" (`BaseResourceValueCheck`) using `ANY_VALUE` as the expected value — meaning the check simply verifies that the relevant expiration attribute is set to *something* (not empty/absent), regardless of the specific date.
- **ARM**: Inspects `properties.rotationPolicy.attributes.expiryTime`. PASSES if any value is present there.
- **Terraform**: Inspects the top-level `expiration_date` attribute on `azurerm_key_vault_key`. PASSES if any value is set.

## Non-compliant example
```hcl
resource "azurerm_key_vault_key" "example" {
  name         = "example-key"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey",
  ]
}
```

## Remediated example
```hcl
resource "azurerm_key_vault_key" "example" {
  name            = "example-key"
  key_vault_id    = azurerm_key_vault.example.id
  key_type        = "RSA"
  key_size        = 2048
  expiration_date = "2027-08-19T00:00:00Z"

  key_opts = [
    "decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey",
  ]
}
```

## Remediation steps
1. Add an `expiration_date` (Terraform, RFC3339 timestamp) to every `azurerm_key_vault_key` resource — or the equivalent `properties.attributes.exp` / `properties.rotationPolicy.attributes.expiryTime` field in ARM/Bicep.
2. Choose an expiration window aligned with your organization's key rotation policy (commonly 1–2 years for encryption keys, shorter for signing keys used in high-risk contexts).
3. Pair this with Key Vault's built-in rotation policy (`azurerm_key_vault_key.rotation_policy` block) to auto-rotate keys before they expire, avoiding a hard outage when the expiry date arrives.
4. Set up Azure Monitor alerts on upcoming key expirations so operations teams have advance notice to rotate dependent application configuration.
5. For keys already in production without an expiration date, plan a controlled rollout: set an expiration date far enough in the future to allow coordinated rotation, rather than retroactively imposing a near-term expiry that could cause an outage.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/KeyExpirationDate.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyExpirationDate.py)
- [Azure Key Vault keys overview](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys)
