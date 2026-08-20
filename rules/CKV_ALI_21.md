# CKV_ALI_21: Ensure API Gateway API Protocol HTTPS
## Severity
**HIGH** (score: 7.5/10)

An API Gateway API configured without an enforced HTTPS protocol allows requests and responses to traverse the network in cleartext, exposing API payloads, tokens, and credentials to interception.

## Summary
This check verifies that every request configuration on an Alibaba Cloud API Gateway API is restricted to the HTTPS protocol.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `alicloud_api_gateway_api`

## Why it matters
An API Gateway endpoint that accepts plain HTTP allows clients (and any network intermediary) to send and receive API traffic — including API keys, tokens, session identifiers, and application payloads — without transport encryption. This exposes the API to eavesdropping and man-in-the-middle tampering/downgrade attacks, and it undermines any authentication scheme layered on top since credentials sent over HTTP can be captured in transit. Restricting the gateway to HTTPS ensures confidentiality and integrity for every request that reaches backend services.

## How Checkov evaluates this
Custom `scan_resource_conf` logic on the `request_config` block(s) of `alicloud_api_gateway_api`:
- If `request_config` is missing or not a list, the check FAILS outright.
- Otherwise, it iterates every `request_config` block; if any block's `protocol` is not exactly `["HTTPS"]` (e.g. `"HTTP"`, `"HTTP,HTTPS"`), the check FAILS on that block.
- Only if **every** `request_config` entry specifies `protocol = "HTTPS"` does the check PASS.

## Non-compliant example
```hcl
resource "alicloud_api_gateway_api" "example" {
  group_id      = alicloud_api_gateway_group.example.id
  name          = "example-api"
  description   = "example description"
  auth_type     = "APP"

  request_config {
    protocol        = "HTTP"     # <-- fails: plaintext HTTP permitted
    method          = "GET"
    path            = "/example"
    mode            = "MAPPING"
  }
}
```

## Remediated example
```hcl
resource "alicloud_api_gateway_api" "example" {
  group_id      = alicloud_api_gateway_group.example.id
  name          = "example-api"
  description   = "example description"
  auth_type     = "APP"

  request_config {
    protocol        = "HTTPS"    # <-- fix: HTTPS-only
    method          = "GET"
    path            = "/example"
    mode            = "MAPPING"
  }
}
```

## Remediation steps
1. Locate every `request_config` block on `alicloud_api_gateway_api` resources.
2. Set `protocol = "HTTPS"` on each block (do not use `"HTTP"` or a mixed value).
3. Ensure a valid TLS certificate is bound to the custom domain associated with the API group, if using a custom domain, so HTTPS termination works correctly.
4. Update client SDKs/integrations to call the HTTPS endpoint; this is generally a non-breaking change if clients already support TLS, but confirm no downstream caller hardcodes an `http://` URL.
5. Re-apply and re-scan to confirm all `request_config` blocks report `HTTPS`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/APIGatewayProtocolHTTPS.py)
- [Alibaba Cloud API Gateway API resource docs](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/api_gateway_api)
