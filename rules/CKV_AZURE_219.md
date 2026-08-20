# CKV_AZURE_219: Ensure Firewall defines a firewall policy
## Severity
**MEDIUM** (score: 5.0/10)

A firewall with no attached firewall policy loses centralized rule governance and threat-intel/IDPS enforcement, weakening consistent network segmentation and control rather than directly exposing a resource.

## Summary
Ensures that a classic `azurerm_firewall` resource is associated with an Azure Firewall Policy, rather than relying solely on the older classic rule-collection model.

## Applicability
- **Terraform**: `azurerm_firewall` — inspects `firewall_policy_id`

## Why it matters
Azure Firewall supports two rule-management models: the legacy "classic rules" model configured directly on the firewall resource, and the newer Firewall Policy model (`azurerm_firewall_policy`), which centralizes rule collections, supports advanced features (TLS inspection, IDPS with Deny mode, DNS proxy, web categories, and policy inheritance across a hub-and-spoke topology), and enables policies to be shared and reused across multiple firewall instances. A firewall with no policy attached is stuck on the classic model and cannot benefit from these more advanced, centrally governed security controls, is harder to standardize across an organization's firewalls (each firewall's rules are managed independently), and complicates auditing since there's no single policy object capturing the intended security posture. Attaching a Firewall Policy is also a prerequisite for using several other hardening capabilities checked separately (e.g., IDPS deny mode in CKV_AZURE_220), so a firewall lacking a policy is effectively unable to adopt those additional controls.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` using `ANY_VALUE` as the expected value on the `firewall_policy_id` attribute. If `firewall_policy_id` is set to any non-empty value, the check **PASSES**. If the attribute is missing or empty, the check **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_firewall" "example" {
  name                = "example-fw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.example.id
    public_ip_address_id = azurerm_public_ip.example.id
  }
  # no firewall_policy_id set
}
```

## Remediated example
```hcl
resource "azurerm_firewall_policy" "example" {
  name                = "example-fw-policy"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard"
}

resource "azurerm_firewall" "example" {
  name                = "example-fw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id  = azurerm_firewall_policy.example.id   # attach a policy

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.example.id
    public_ip_address_id = azurerm_public_ip.example.id
  }
}
```

## Remediation steps
1. Create an `azurerm_firewall_policy` resource (and any `azurerm_firewall_policy_rule_collection_group` resources needed to carry over your existing rules).
2. Set `firewall_policy_id` on the `azurerm_firewall` resource to the new policy's ID.
3. Migrate any existing classic `network_rule_collection`/`application_rule_collection`/`nat_rule_collection` blocks defined directly on the firewall into equivalent rule collection groups on the policy — Azure does not allow both classic rules and a policy to be active simultaneously in the same way, so plan the cutover carefully to avoid a rule-coverage gap.
4. Consider adopting a hub firewall policy plus child policies (`base_policy_id`) if managing multiple firewalls across a hub-and-spoke network, to centralize governance.
5. This change may require careful sequencing/downtime planning in production, since converting from classic rules to policy-based rules is not a simple in-place attribute flip in Azure — validate in a non-production environment first.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureFirewallDefinesPolicy.py
- Azure docs: https://learn.microsoft.com/en-us/azure/firewall-manager/policy-overview
