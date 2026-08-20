# CKV_AZURE_114: Ensure that key vault secrets have "content_type" set
## Severity
**LOW** (score: 2.0/10)

Missing a content_type label on a Key Vault secret is a metadata/organizational hygiene gap with no direct effect on confidentiality, integrity, or availability.

## Summary
This check ensures that every Azure Key Vault secret has its `content_type` metadata field populated, documenting what kind of value the secret holds.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_key_vault_secret` (inspects `content_type`)
- **ARM/Bicep**: `Microsoft.KeyVault/vaults/secrets` (inspects `properties/contentType`)

## Why it matters
`content_type` is metadata, not a security boundary in itself, but it plays an important operational-security role: it tells consuming applications, operators, and automated rotation tooling what format the secret's value is in (e.g., `application/json`, `text/plain`, `password`, a connection-string format) so it can be parsed, validated, and rotated correctly. Secrets without a content type are frequently mishandled — e.g., a rotation script that doesn't know a secret is actually a structured connection string may replace it incorrectly, or an application may fail to parse it, leading to either an outage or, worse, a script logging/mishandling a secret because its structure wasn't understood. Consistently tagging secrets with content type also supports auditing and inventory efforts (knowing at a glance which secrets are certificates, passwords, keys, or tokens) which is valuable when responding to an incident and needing to assess blast radius quickly.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using the `ANY_VALUE` sentinel:
- **Terraform**: inspects `content_type` on `azurerm_key_vault_secret`. Any non-empty value **PASSES**; if the attribute is absent/unset, the check **FAILS**.
- **ARM**: inspects `properties/contentType` with the same logic.

## Non-compliant example
```hcl
resource "azurerm_key_vault_secret" "bad_example" {
  name         = "bad-secret"
  value        = var.db_connection_string
  key_vault_id = azurerm_key_vault.example.id

  # No content_type set
}
```

## Remediated example
```hcl
resource "azurerm_key_vault_secret" "good_example" {
  name         = "good-secret"
  value        = var.db_connection_string
  key_vault_id = azurerm_key_vault.example.id

  # Fix: document what kind of value this secret holds
  content_type = "text/plain; charset=utf-8; format=connection-string"
}
```

## Remediation steps
1. Add a `content_type` attribute (Terraform) or `properties.contentType` (ARM/Bicep) to every `azurerm_key_vault_secret`/`Microsoft.KeyVault/vaults/secrets` resource.
2. Use a consistent, meaningful convention across the team/org (e.g., MIME types like `application/json`, or descriptive labels like `password`, `connection-string`, `api-key`, `certificate-pem`) so tooling and humans can rely on it.
3. For secrets managed outside of Terraform/ARM (e.g., populated by a rotation pipeline via the Azure CLI/SDK), ensure the pipeline also sets `contentType` when writing new secret versions, since Checkov only evaluates what is declared in IaC.
4. Treat this as a low-risk, easy-to-batch fix — it does not require downtime or resource replacement, just a metadata update on existing secret resources.
5. Consider adding this as a required field via a policy-as-code check or PR template so new secrets aren't added without it going forward.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/SecretContentType.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecretContentType.py)
- [Azure docs: About Azure Key Vault secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets)
