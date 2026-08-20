# CKV_AZURE_121: Ensure that Azure Front Door enables WAF
## Severity
**LOW** (score: 2.0/10)

Lacking WAF protection on a globally distributed edge entry point leaves backend applications exposed to common web-layer attacks that the WAF would otherwise block before reaching origin servers.

## Summary
This check verifies that an Azure Front Door (classic) frontend endpoint has a Web Application Firewall policy linked to it, so traffic passing through Front Door is inspected for common web attacks.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **IaC frameworks:** Terraform, ARM templates, Bicep
- **Resource types:**
  - Terraform: `azurerm_frontdoor`
  - ARM: `Microsoft.Network/frontDoors`

## Why it matters
Azure Front Door is typically deployed as the internet-facing entry point for global applications (CDN + load balancing + TLS termination), meaning it sits directly in the path of all inbound internet traffic before it reaches backend origins. If no WAF policy is linked, Front Door simply forwards all requests — including malicious payloads such as SQL injection, XSS, and known bot/scanner traffic — straight to backend services. Because Front Door is the first point of contact for global users, it's an ideal place to block attacks cheaply and at scale before they consume backend compute or hit application code; skipping WAF here means every backend service must independently defend against the exact same attack classes, which is both redundant and error-prone across large or multi-team estates.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects whether a WAF policy is linked to the Front Door's frontend endpoint:
- Terraform: inspects `frontend_endpoint[0].web_application_firewall_policy_link_id`.
- ARM: inspects `properties.frontendEndpoints[0].properties.webApplicationFirewallPolicyLink.id`.
- **PASS** if this attribute is set to any non-empty value (`ANY_VALUE` — the check doesn't validate the specific policy, only that one is linked).
- **FAIL** if the attribute is absent or empty.

## Non-compliant example
```hcl
resource "azurerm_frontdoor" "example" {
  name                = "fd-example"
  resource_group_name = azurerm_resource_group.example.name

  frontend_endpoint {
    name      = "fd-example-frontend"
    host_name = "fd-example.azurefd.net"
    # no web_application_firewall_policy_link_id set
  }

  routing_rule {
    name               = "example-routing-rule"
    accepted_protocols = ["Http", "Https"]
    patterns_to_match  = ["/*"]
    frontend_endpoints = ["fd-example-frontend"]
    forwarding_configuration {
      forwarding_protocol = "MatchRequest"
      backend_pool_name   = "example-backend-pool"
    }
  }

  # ... backend_pool / backend_pool_health_probe / backend_pool_load_balancing omitted for brevity
}
```

## Remediated example
```hcl
resource "azurerm_frontdoor_firewall_policy" "example" {
  name                = "fdwafpolicy"
  resource_group_name = azurerm_resource_group.example.name
  enabled             = true
  mode                = "Prevention"

  managed_rule {
    type    = "DefaultRuleSet"
    version = "1.0"
  }
}

resource "azurerm_frontdoor" "example" {
  name                = "fd-example"
  resource_group_name = azurerm_resource_group.example.name

  frontend_endpoint {
    name                                = "fd-example-frontend"
    host_name                          = "fd-example.azurefd.net"
    web_application_firewall_policy_link_id = azurerm_frontdoor_firewall_policy.example.id  # WAF now linked
  }

  routing_rule {
    name               = "example-routing-rule"
    accepted_protocols = ["Http", "Https"]
    patterns_to_match  = ["/*"]
    frontend_endpoints = ["fd-example-frontend"]
    forwarding_configuration {
      forwarding_protocol = "MatchRequest"
      backend_pool_name   = "example-backend-pool"
    }
  }
}
```

## Remediation steps
1. Create an `azurerm_frontdoor_firewall_policy` (or `Microsoft.Network/FrontDoorWebApplicationFirewallPolicies` in ARM) with a managed rule set (e.g. `DefaultRuleSet` or OWASP CRS) and `mode = "Prevention"` or `"Detection"`.
2. Set `web_application_firewall_policy_link_id` on the Front Door's `frontend_endpoint` block to reference the policy's ID (Terraform), or `properties.frontendEndpoints[].properties.webApplicationFirewallPolicyLink.id` (ARM).
3. Start with `Detection` mode to observe false positives across your production traffic before switching to `Prevention`.
4. Note that Azure Front Door (classic) is being succeeded by Azure Front Door Standard/Premium (`azurerm_cdn_frontdoor_*` resources), which have their own separate WAF association model — verify which SKU you're using.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureFrontDoorEnablesWAF.py)
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureFrontDoorEnablesWAF.py)
- [Azure Front Door WAF documentation](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview)
