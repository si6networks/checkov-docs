# CKV_AZURE_39: Ensure that no custom subscription owner roles are created

## Severity
**HIGH** (score: 7.5/10)

A custom role definition scoped to a subscription can grant effectively unrestricted, owner-equivalent privileges, enabling privilege escalation and full control over all resources in that subscription.

## Summary
This check flags custom Azure RBAC role definitions that grant full wildcard (`*`) actions while being assignable at the subscription scope, effectively recreating the built-in Owner role.

## Applicability
- **Terraform**: `azurerm_role_definition`
- **ARM templates**: `Microsoft.Authorization/roleDefinitions`
- **Bicep**: `Microsoft.Authorization/roleDefinitions`

## Why it matters
Azure's built-in "Owner" role is intentionally a single, well-known, auditable role that grants unrestricted control (including the ability to grant others access) over a scope. When teams create *custom* roles that also grant `*` (all actions) and assign them at the subscription scope, they defeat the purpose of using RBAC to enforce least privilege: it becomes harder for security teams to reason about "who has Owner-equivalent access" because that access is now scattered across differently-named custom roles instead of concentrated in the well-monitored built-in Owner role. This also complicates access reviews, conditional access policies, and Privileged Identity Management (PIM) workflows that are often scoped specifically to the built-in Owner/Contributor/User Access Administrator roles. A custom "owner-equivalent" role can slip past governance controls that specifically alert on built-in Owner assignments.

## How Checkov evaluates this
- **ARM**: Reads `properties.assignableScopes`. If any scope string matches a subscription-level pattern (root `/`, `/subscriptions/<guid>`, or the ARM expression `[subscription().id]`), it then inspects `properties.permissions`. If any permission entry's `actions` list contains the wildcard `"*"`, the check FAILS. Otherwise PASSES.
- **Terraform**: Reads `permissions[0].actions`. If any action string contains `"*"`, FAILS. Otherwise PASSES. (Note the Terraform implementation does not separately check `assignable_scopes` — any role with a wildcard action fails regardless of scope, which is a stricter/simplified version of the ARM logic.)

## Non-compliant example
```hcl
resource "azurerm_role_definition" "example" {
  name        = "custom-owner-role"
  scope       = data.azurerm_subscription.primary.id
  description = "Custom role with full access"

  permissions {
    actions     = ["*"]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.primary.id,
  ]
}
```

## Remediated example
```hcl
resource "azurerm_role_definition" "example" {
  name        = "custom-storage-admin-role"
  scope       = data.azurerm_subscription.primary.id
  description = "Custom role limited to storage account management"

  permissions {
    actions = [
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Storage/storageAccounts/write",
      "Microsoft.Storage/storageAccounts/listkeys/action",
    ]
    not_actions = []
  }

  assignable_scopes = [
    data.azurerm_subscription.primary.id,
  ]
}
```

## Remediation steps
1. Identify the intended purpose of the custom role and enumerate the specific `Microsoft.<Provider>/.../read|write|action` permission strings actually required — avoid the `*` wildcard.
2. If genuinely full administrative access is needed, assign the built-in `Owner` role instead of creating a custom equivalent, so it remains visible to standard governance tooling (Access Reviews, PIM, Azure Policy).
3. If a custom role must exist for a legitimate reason (e.g., an internal naming convention), scope its `assignable_scopes` to a resource group or resource, not the subscription, to limit blast radius.
4. Periodically audit custom role definitions with Azure Policy or Resource Graph queries for any that combine `*` actions with subscription-level assignable scopes.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/CustomRoleDefinitionSubscriptionOwner.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CutsomRoleDefinitionSubscriptionOwner.py)
- [Azure custom roles documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)
