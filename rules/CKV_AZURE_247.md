# CKV_AZURE_247: Ensure that Azure Cognitive Services account hosted with OpenAI is configured with data loss prevention

## Severity
**HIGH** (score: 7.5/10)

Without outbound network restriction and FQDN allow-listing, an Azure OpenAI Cognitive Services account can send prompts and completions to arbitrary external endpoints, creating a data-exfiltration channel for potentially sensitive input data.

## Summary
For Azure Cognitive Services accounts of kind `OpenAI`, this check ensures outbound network access is restricted and an explicit allow-list of outbound FQDNs is configured, preventing the deployed model endpoint from communicating with arbitrary external destinations.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `azurerm_cognitive_account` (only when `kind = "OpenAI"`; all other kinds automatically pass)

## Why it matters
Azure OpenAI resources can process highly sensitive prompts and completions (proprietary source code, customer PII, internal documents fed via RAG or fine-tuning). If the account's outbound network path is unrestricted, a compromised dependency, malicious plugin/tooling, or a prompt-injection-driven tool call could exfiltrate that data to an attacker-controlled endpoint over the account's egress path. Restricting outbound network access and only allow-listing specific FQDNs (a form of data-loss-prevention/egress control) closes that exfiltration channel, ensuring the resource can only reach known-good destinations (e.g., specific storage accounts or private endpoints) instead of the open internet.

## How Checkov evaluates this
The check (a `BaseResourceCheck`) first looks at `kind`:
- If `kind` is not `"openai"` (case-insensitive), the check **auto-PASSes** — it does not apply to non-OpenAI Cognitive Services kinds.
- If `kind` is `openai`, it reads two attributes:
  - `outbound_network_access_restricted`
  - `fqdns` (the outbound-allowed FQDN list)
- **FAIL** if `outbound_network_access_restricted` is falsy/unset, OR `fqdns` is empty/unset.
- **PASS** only if `outbound_network_access_restricted` is truthy AND `fqdns` contains at least one entry.

## Non-compliant example
```hcl
resource "azurerm_cognitive_account" "openai" {
  name                = "example-openai"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  kind                = "OpenAI"
  sku_name            = "S0"
  # outbound_network_access_restricted not set -> defaults to unrestricted
  # fqdns not set
}
```

## Remediated example
```hcl
resource "azurerm_cognitive_account" "openai" {
  name                = "example-openai"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  kind                = "OpenAI"
  sku_name            = "S0"

  outbound_network_access_restricted = true                       # added
  fqdns = [                                                        # added
    "myinternalstorage.blob.core.windows.net",
    "approved-vector-db.internal.contoso.com",
  ]
}
```

## Remediation steps
1. Set `outbound_network_access_restricted = true` on every `azurerm_cognitive_account` with `kind = "OpenAI"`.
2. Populate `fqdns` with the specific, minimal set of destinations the deployment genuinely needs to reach (e.g., a storage account for embeddings, an internal vector database, approved plugin endpoints).
3. Combine this with private endpoints / VNet integration for inbound traffic to fully close both ingress and egress exposure.
4. Re-validate any downstream integrations (plugins, function calling, data connectors) after restricting egress — anything not in the FQDN list will start failing.
5. Requires an Azure OpenAI resource kind that supports outbound network restrictions (check current API/provider version support before applying to existing production accounts).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/OpenAICognitiveServicesRestrictOutboundNetwork.py)
- [Azure OpenAI network security guidance](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/network-security)
