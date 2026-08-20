# CKV_SECRET_3: Azure Storage Account access key

## Severity
**HIGH** (score: 7.5/10)

An Azure Storage account key is a non-expiring master credential granting full read/write/delete control over all data in the account and the ability to mint arbitrary long-lived SAS tokens, making it one of the highest blast-radius credentials to leak.

## Summary
This check scans file contents for hardcoded Azure Storage Account access keys (the shared keys used for Storage account authentication), flagging static, full-control credentials committed directly into source or config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (Terraform, ARM/Bicep templates, connection strings in app config/YAML/`.env` files, scripts, CI definitions, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level.

## Why it matters
An Azure Storage Account access key is a master credential: it grants full read/write/delete access to every container, blob, queue, table, and file share in that storage account, and can also be used to generate SAS tokens with arbitrary permissions and expiry. There are only two of these keys per account, they never expire on their own, and possession of either one is equivalent to full administrative control over the account's data plane. A leaked key in a public or over-shared repository lets an attacker exfiltrate all stored data (which frequently includes backups, logs, or application data with PII), delete data for ransom/extortion, or mint long-lived SAS tokens that persist access even after the key itself is rotated (since SAS tokens generated before rotation using the old key remain valid until they expire or the key is regenerated). This makes it one of the highest-blast-radius credential types to leak in Azure.

## How Checkov evaluates this
The secrets scanner matches the structural signature of Azure Storage account keys — commonly appearing inside a connection string (`AccountKey=...;`) or as a standalone value — which are base64-encoded, fixed-length (88 characters, always ending in `==` padding). The detector looks for this base64/length/padding signature (and, in connection-string form, the `AccountKey=` marker) in scanned file content; a match is reported as a FAIL at that file/line. Presence alone triggers the finding — there is no resource-configuration condition to evaluate.

## Non-compliant example
```json
{
  "ConnectionStrings": {
    "Storage": "DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=Xy8kP2qzR7mNc1vLj9Wb4Hs6Ft0Dg3Ea5Cr8Ux2Yn7Bp4Vk1Qm6Ws9Zt3Jd5Fh==;EndpointSuffix=core.windows.net"
  }
}
```

## Remediated example
```json
{
  "ConnectionStrings": {
    "Storage": "@Microsoft.KeyVault(SecretUri=https://mycompany-kv.vault.azure.net/secrets/storage-conn-string/)"
  }
}
```

## Remediation steps
1. Regenerate the exposed storage account key immediately in the Azure Portal (Storage Account → Access keys → Rotate key) — treat it as compromised.
2. Replace the hardcoded connection string/key with a reference to Azure Key Vault, or better, switch the application to Azure AD (Microsoft Entra ID) authentication / managed identity for the storage account instead of shared-key auth entirely.
3. If shared-key auth must remain for legacy reasons, disable it at the account level (`allowSharedKeyAccess = false` in Terraform/ARM) once all consumers have migrated off it, so leaked keys become useless.
4. Purge the secret from git history if it was ever committed/pushed.
5. Rotate both keys (primary and secondary) on a regular schedule and update all consumers via the automated Key Vault reference rather than manual redeploys.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
- [Azure: Manage storage account access keys](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)
