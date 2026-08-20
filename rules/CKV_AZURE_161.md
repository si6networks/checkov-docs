# CKV_AZURE_161: Ensures Spring Cloud API Portal is enabled on for HTTPS

## Severity
**HIGH** (score: 7.0/10)

Not enforcing HTTPS-only on the Spring Cloud API Portal permits plaintext HTTP traffic, exposing API requests, responses, and any embedded credentials or tokens to network interception.

## Summary
This check ensures that an Azure Spring Cloud (Azure Spring Apps) API Portal instance enforces HTTPS-only access rather than allowing plain HTTP.

## Applicability
- **Framework:** Terraform (Azure provider)
- **Resource type:** `azurerm_spring_cloud_api_portal`

## Why it matters
The API Portal is a developer-facing interface for exploring and testing APIs exposed by an Azure Spring Apps service — it can expose API documentation, endpoint metadata, and potentially test/trial invocations. If HTTPS-only is not enforced, traffic to the portal (including any credentials or tokens used to authenticate to it, and any sensitive API metadata it renders) can be transmitted or intercepted over plaintext HTTP, exposing it to network eavesdropping and man-in-the-middle attacks. Enforcing HTTPS-only ensures all portal traffic is encrypted in transit.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `https_only_enabled`:
- **PASS** if the value is `true`.
- **FAIL** if `false`, or if the attribute is missing (default missing-block behavior for `BaseResourceValueCheck` is FAILED).

## Non-compliant example
```hcl
resource "azurerm_spring_cloud_api_portal" "example" {
  name                    = "example-portal"
  spring_cloud_service_id = azurerm_spring_cloud_service.example.id

  # https_only_enabled omitted -> plain HTTP access permitted
}
```

## Remediated example
```hcl
resource "azurerm_spring_cloud_api_portal" "example" {
  name                    = "example-portal"
  spring_cloud_service_id = azurerm_spring_cloud_service.example.id

  https_only_enabled = true   # forces HTTPS-only access to the portal
}
```

## Remediation steps
1. Add `https_only_enabled = true` to every `azurerm_spring_cloud_api_portal` resource.
2. This is an in-place configuration change and does not require replacement of the underlying Spring Cloud service.
3. Verify any internal tooling or documentation links pointing at the portal use `https://` URLs after enabling.
4. Pair this with restricting public network access on the portal (see CKV_AZURE_162) for defense in depth.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SpringCloudAPIPortalHTTPSOnly.py)
- [Azure Spring Apps API portal documentation](https://learn.microsoft.com/en-us/azure/spring-apps/how-to-use-api-portal)
