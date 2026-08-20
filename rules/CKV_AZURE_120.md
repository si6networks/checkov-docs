# CKV_AZURE_120: Ensure that Application Gateway enables WAF
## Severity
**LOW** (score: 2.0/10)

Without a Web Application Firewall, internet-facing applications behind the gateway are left exposed to common web exploitation techniques such as SQL injection and cross-site scripting.

## Summary
This graph-based check verifies that an Azure Application Gateway has a Web Application Firewall (WAF) enabled, either via its own inline `waf_configuration` block or via an attached `azurerm_web_application_firewall_policy` with policy settings enabled.

## Applicability
- **IaC framework:** Terraform (Azure provider)
- **Resource types:** `azurerm_application_gateway`, `azurerm_web_application_firewall_policy`

## Why it matters
An Application Gateway without WAF enabled is a plain Layer-7 reverse proxy/load balancer with no protection against common web application attacks — SQL injection, cross-site scripting, remote file inclusion, and other OWASP Top 10 attack patterns pass straight through to the backend application. WAF (backed by the OWASP Core Rule Set on Azure) inspects and can block these malicious requests before they ever reach application code, providing a critical layer of defense especially for internet-facing applications where patching every backend vulnerability instantly is impractical. Omitting WAF is a frequent root cause in incidents where a known web application vulnerability (e.g. an unpatched CMS plugin) is exploited directly because there was no compensating control in front of it.

## How Checkov evaluates this
This is a graph-based JSON policy that filters for `azurerm_application_gateway` resources and passes if **either** of these conditions holds:
1. The gateway's own `waf_configuration.enabled` attribute equals `true` (the legacy, gateway-embedded WAF configuration), **or**
2. The gateway has a connection to an `azurerm_web_application_firewall_policy` resource (the modern, WAF-policy-based approach used with Application Gateway v2 SKUs) **and** that policy's `policy_settings.enabled` attribute equals `true`.

**FAIL** if neither condition is satisfied — i.e., no WAF configuration block with `enabled = true`, and no connected, enabled WAF policy.

## Non-compliant example
```hcl
resource "azurerm_application_gateway" "example" {
  name                = "appgw-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }

  # no waf_configuration block and no attached WAF policy
  gateway_ip_configuration {
    name      = "gw-ip-config"
    subnet_id = azurerm_subnet.example.id
  }

  # ... frontend/backend/listener/rule blocks omitted for brevity
}
```

## Remediated example
```hcl
resource "azurerm_web_application_firewall_policy" "example" {
  name                = "waf-policy-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"

  policy_settings {
    enabled = true
    mode    = "Prevention"
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
  }
}

resource "azurerm_application_gateway" "example" {
  name                = "appgw-example"
  resource_group_name = azurerm_resource_group.example.name
  location             = "eastus"
  firewall_policy_id  = azurerm_web_application_firewall_policy.example.id  # attaches an enabled WAF policy

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }

  gateway_ip_configuration {
    name      = "gw-ip-config"
    subnet_id = azurerm_subnet.example.id
  }

  # ... frontend/backend/listener/rule blocks omitted for brevity
}
```

## Remediation steps
1. Use a WAF-capable SKU tier (`WAF_v2` or `WAF`) for the Application Gateway.
2. Either set `waf_configuration { enabled = true, firewall_mode = "Prevention" }` directly on the gateway (legacy approach), or create an `azurerm_web_application_firewall_policy` with `policy_settings { enabled = true }` and attach it via `firewall_policy_id`.
3. Include a managed rule set (e.g. OWASP CRS 3.2) in the WAF policy so it actually has rules to enforce.
4. Start in `Detection` mode and review logs for false positives before switching to `Prevention` mode, to avoid blocking legitimate traffic.
5. Changing the SKU tier (e.g. `Standard_v2` to `WAF_v2`) may require planning for downtime/resource replacement depending on your existing gateway configuration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azure/ApplicationGatewayEnablesWAF.json)
- [Azure Application Gateway WAF documentation](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview)
