# CKV_AZURE_87: Ensure that Azure Defender is set to On for Key Vault
## Severity
**LOW** (score: 2.0/10)

Failing to enable Azure Defender (threat protection) on Key Vault removes anomaly and intrusion detection for a service that stores secrets, keys, and certificates, delaying detection of an active compromise rather than causing one by itself.

## Summary
This check verifies that Microsoft Defender for Cloud (formerly Azure Security Center / "Azure Defender") is enabled with the Standard pricing tier for the Key Vault resource type at the subscription level.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_security_center_subscription_pricing`
- **ARM templates**: `Microsoft.Security/pricings`
- **Bicep**: resources compiling to `Microsoft.Security/pricings`

## Why it matters
Azure Key Vault stores secrets, encryption keys, and certificates that are often the "keys to the kingdom" for an environment — TLS private keys, database connection strings, service principal credentials, etc. Without Microsoft Defender for Key Vault enabled, Azure will not perform advanced threat detection on vault access patterns, such as:
- Suspicious access patterns from unfamiliar IP addresses or Tor exit nodes
- Access attempts from malware-linked IPs
- Unusual volumes of secret/key retrieval that could indicate a compromised application or insider exfiltrating credentials
- Suspicious operations performed by users who have never accessed the vault before

Leaving this off means an attacker who obtains valid access to pull secrets from Key Vault (e.g. via a compromised managed identity or leaked access policy) can operate silently, with no anomaly-detection alerting the security team.

## How Checkov evaluates this
- **Terraform**: The check inspects the `azurerm_security_center_subscription_pricing` resource. It PASSES if `resource_type != "KeyVaults"` (not applicable) OR if `tier == "Standard"`. It FAILS only when `resource_type == "KeyVaults"` and `tier` is anything other than `"Standard"` (e.g. `"Free"`).
- **ARM**: Looks at `properties.pricingTier` and `name` in the `Microsoft.Security/pricings` resource. PASSES only when `name == "KeyVaults"` and `properties.pricingTier == "Standard"`; otherwise FAILS.

## Non-compliant example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Free"
  resource_type = "KeyVaults"
}
```

## Remediated example
```hcl
resource "azurerm_security_center_subscription_pricing" "example" {
  tier          = "Standard"   # <-- enables Defender for Key Vault
  resource_type = "KeyVaults"
}
```

## Remediation steps
1. Add (or update) an `azurerm_security_center_subscription_pricing` resource with `resource_type = "KeyVaults"`.
2. Set `tier = "Standard"` to enable Defender for this resource type at the subscription scope.
3. Note that Defender for Key Vault is billed per protected vault — factor this into cost planning before enabling broadly.
4. Apply the change; Azure Defender coverage is subscription-wide, so this only needs to be declared once per subscription, not per vault.
5. Confirm in the Azure Portal under **Microsoft Defender for Cloud > Environment Settings** that "Key Vault" shows as "On".

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKeyVaults.py
- Checkov check source (ARM): https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureDefenderOnKeyVaults.py
