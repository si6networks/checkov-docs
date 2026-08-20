# CKV_AZURE_248: Ensure that if Azure Batch account public network access in case 'enabled' then its account access must be 'deny'

## Severity
**HIGH** (score: 7.5/10)

Allowing public network access to a Batch account without a default-deny policy exposes the account's management/job-submission endpoints to the internet, enabling unauthorized job submission or data access.

## Summary
This check ensures that when an Azure Batch account has public network access enabled, its account-access network profile does not use a default action of "allow" — i.e., public exposure must still be gated by an explicit deny-by-default posture with allow-listed exceptions.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Frameworks:** Terraform, Bicep, ARM (`arm`)
- **Resource types:** `azurerm_batch_account` (Terraform), `Microsoft.Batch/batchAccounts` (ARM/Bicep)

## Why it matters
Azure Batch accounts orchestrate compute jobs and can hold pool/job credentials, storage keys, and task metadata. If public network access is enabled but the account-access network profile defaults to "allow" all traffic, then anyone on the internet can reach the Batch account's endpoint without needing to be on an allow-list — turning "public access enabled" into "public access unrestricted." A default action of "Deny" combined with specific IP-rule exceptions ensures that even when the account is reachable from the public internet, only explicitly trusted source ranges can actually connect, dramatically reducing the attack surface for credential-stuffing, DoS, or unauthorized job submission.

## How Checkov evaluates this
The Terraform check (`BaseResourceCheck`) reads `public_network_access_enabled`:
- If it is explicitly `false`, the check **PASSes** (no need to inspect account access rules).
- If public access is not disabled, it looks at `network_profile[0].account_access[0].default_action`.
  - If there is no `network_profile`, no `account_access` block, or no `default_action` — **PASS** (nothing forcing an "allow" posture is configured).
  - **FAIL** only if `default_action` is present and equals `"allow"` (case-insensitive) while public network access is not disabled.

The ARM/Bicep variant mirrors this logic against `properties.publicNetworkAccess`, `properties.networkProfile.accountAccess.defaultAction`, checking for `"disabled"` vs. a forbidden `"allow"` default action.

## Non-compliant example
```hcl
resource "azurerm_batch_account" "example" {
  name                = "examplebatchaccount"
  resource_group_name = azurerm_resource_group.example.name
  location            = "eastus"
  pool_allocation_mode = "BatchService"

  public_network_access_enabled = true

  network_profile {
    account_access {
      default_action = "Allow"   # allows all public traffic by default
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_batch_account" "example" {
  name                = "examplebatchaccount"
  resource_group_name = azurerm_resource_group.example.name
  location            = "eastus"
  pool_allocation_mode = "BatchService"

  public_network_access_enabled = true

  network_profile {
    account_access {
      default_action = "Deny"    # was "Allow"

      ip_rule {
        action     = "Allow"
        ip_range   = "203.0.113.0/24"   # trusted corporate egress range
      }
    }
  }
}
```

## Remediation steps
1. If public network access is not required at all, set `public_network_access_enabled = false` — this satisfies the check without needing any network profile.
2. If public access must remain enabled, set `network_profile.account_access.default_action = "Deny"`.
3. Add explicit `ip_rule` blocks for every trusted source range that legitimately needs to reach the account.
4. Prefer using a Private Endpoint for the Batch account where possible instead of relying solely on public access with IP allow-listing.
5. Test job submission and pool management connectivity from your allow-listed ranges after the change, since anything not explicitly allowed will be blocked.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureBatchAccountEndpointAccessDefaultAction.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureBatchAccountEndpointAccessDefaultAction.py)
- [Azure Batch account network configuration](https://learn.microsoft.com/en-us/azure/batch/batch-network-securities-management)
