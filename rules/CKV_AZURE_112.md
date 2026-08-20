# CKV_AZURE_112: Ensure that key vault key is backed by HSM
## Severity
**LOW** (score: 2.0/10)

Software-protected keys already benefit from Key Vault's access controls, so lacking HSM backing mainly reduces assurance against key extraction under a deeper platform or host compromise rather than creating a direct exposure.

## Summary
This check ensures that a key stored in Azure Key Vault is generated/protected by a Hardware Security Module (HSM) rather than by software-based cryptography.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_key_vault_key` (inspects `key_type`)
- **ARM/Bicep**: `Microsoft.KeyVault/vaults/keys` (inspects `properties/kty`)

## Why it matters
Software-protected keys are generated and used within Key Vault's software cryptographic provider; while the key material is encrypted at rest and access-controlled, the private key can, in principle, be extracted from memory/process space under certain attack scenarios (e.g., a compromised host with sufficient privileges, certain classes of side-channel or memory-disclosure vulnerabilities). HSM-backed keys are generated inside, and never leave, a FIPS 140-2 Level 2/3-validated hardware security module — cryptographic operations are performed inside the HSM boundary, so the private key material is never exposed in plaintext to the host OS, hypervisor, or Key Vault's own software stack. For keys protecting highly sensitive data (root encryption keys, keys used for regulatory-mandated cryptographic operations, keys protecting other keys), HSM backing is often a hard compliance requirement (e.g., PCI-DSS HSM requirements for cardholder data key management) and meaningfully raises the bar against key exfiltration.

## How Checkov evaluates this
- **Terraform**: inspects `key_type` on `azurerm_key_vault_key`. The check **PASSES** if the value is `"RSA-HSM"` or `"EC-HSM"` (via `get_expected_values`); any other value (e.g., `"RSA"`, `"EC"`, `"oct"`) **FAILS**.
- **ARM**: inspects `properties/kty` with the same accepted values, `"RSA-HSM"` or `"EC-HSM"`.

## Non-compliant example
```hcl
resource "azurerm_key_vault_key" "bad_example" {
  name         = "bad-key"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}
```

## Remediated example
```hcl
resource "azurerm_key_vault_key" "good_example" {
  name         = "good-key"
  key_vault_id = azurerm_key_vault.example.id
  # Fix: use an HSM-backed key type instead of software-protected RSA
  key_type     = "RSA-HSM"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}
```

## Remediation steps
1. Change `key_type` (Terraform) / `properties.kty` (ARM/Bicep) from `RSA`/`EC` to `RSA-HSM`/`EC-HSM`.
2. Ensure the target Key Vault is a **Premium** SKU vault (`sku_name = "premium"`) — HSM-backed keys require the Premium tier; Standard-tier vaults do not support them.
3. Note this typically requires creating a new key (key type cannot usually be changed in place) and re-encrypting/re-wrapping any data or keys that depended on the old software key, with a coordinated rotation.
4. Update any dependent resources (disk encryption sets, CMK references on storage/SQL/Cosmos DB, etc.) to reference the new HSM-backed key version.
5. Factor in the additional cost of Premium-tier Key Vault and HSM-backed key operations when budgeting.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/KeyBackedByHSM.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyBackedByHSM.py)
- [Azure docs: About keys, secrets, and certificates](https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates)
