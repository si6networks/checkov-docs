# CKV_AZURE_167: Ensure a retention policy is set to cleanup untagged manifests

## Severity
**LOW** (score: 2.0/10)

Missing retention policy for untagged manifests is primarily a storage-hygiene and cost concern, with only marginal security benefit from reducing stale image sprawl.

## Summary
This check ensures that an Azure Container Registry has a retention policy configured to automatically clean up untagged image manifests after a set number of days.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_container_registry` resource.

## Why it matters
Untagged manifests accumulate whenever images are overwritten/retagged (e.g., repeatedly pushing `latest`), leaving orphaned layers behind. While primarily a storage-cost and hygiene concern, unmanaged accumulation of stale, untagged image content also increases the attack surface for registry-level exploration: old, unpatched image layers remain retrievable by digest indefinitely, potentially exposing outdated software with known vulnerabilities to anyone with pull access, and complicating incident response/forensics when trying to determine what was actually deployed at a point in time. A retention policy enforces automatic cleanup so the registry doesn't silently retain a long tail of un-vetted, un-inventoried content.

## How Checkov evaluates this
The check (`ACREnableRetentionPolicy`) passes if either:
- `retention_policy_in_days` is present on the resource (newer provider attribute), or
- a `retention_policy` block is present with `enabled = true`.

If neither is configured, the check **FAILS**. This is a Premium-SKU-only ACR feature.

## Non-compliant example
```hcl
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"
  # No retention_policy / retention_policy_in_days configured
}
```

## Remediated example
```hcl
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"

  retention_policy {
    days    = 7
    enabled = true
  }
}
```

## Remediation steps
1. Confirm the ACR SKU is `Premium` — retention policies require this tier.
2. Add a `retention_policy` block with `enabled = true` and an appropriate `days` value (or set `retention_policy_in_days` on providers exposing the newer attribute name).
3. Choose a retention window that balances rollback needs (ability to re-pull a recently untagged image) against storage cost and hygiene.
4. Combine with a tagging strategy (immutable tags, semantic versioning) so that important images are never left untagged accidentally.
5. Verify the current `azurerm` provider version's attribute name, as Microsoft/HashiCorp have moved between `retention_policy` blocks and flattened attributes across versions.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACREnableRetentionPolicy.py
