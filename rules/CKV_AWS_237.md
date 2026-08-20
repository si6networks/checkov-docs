# CKV_AWS_237: Ensure Create before destroy for API Gateway

## Severity
**LOW** (score: 2.0/10)

This check guards against an outage during forced API Gateway replacement and has no direct confidentiality, integrity, or access-control impact.

## Summary
This check ensures that `aws_api_gateway_rest_api` resources declare a `lifecycle { create_before_destroy = true }` block, so a replacement API is created before the old one is torn down.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_api_gateway_rest_api`

## Why it matters
Certain changes to an `aws_api_gateway_rest_api` resource (for example, changing `name`, `endpoint_configuration`, or other immutable attributes) force Terraform to destroy and recreate the API. By default, Terraform destroys the existing resource first and creates its replacement afterward. For an API Gateway REST API that is actively serving production traffic — potentially fronting critical backend services via Lambda integrations, VPC links, or HTTP proxies — this default ordering means there is a window during which the API, its stages, deployments, custom domain mappings, and usage plans simply do not exist, causing a hard outage for every client of that API. This is purely an availability/reliability risk category (`GENERAL_SECURITY` in Checkov's categorization, though the actual concern is uptime), but availability failures during infrastructure changes are a common trigger for rushed, poorly-reviewed emergency fixes that can themselves introduce security regressions (e.g. temporarily relaxing an authorizer or WAF association to "get things working again"). Enforcing `create_before_destroy = true` removes this entire class of self-inflicted outage.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `lifecycle[0].create_before_destroy` on the `aws_api_gateway_rest_api` resource.
- **PASS** if `create_before_destroy` is explicitly set to `true`.
- **FAIL** if the `lifecycle` block is absent, or `create_before_destroy` is missing or `false`.

## Non-compliant example
```hcl
resource "aws_api_gateway_rest_api" "api" {
  name = "orders-api"
}
```

## Remediated example
```hcl
resource "aws_api_gateway_rest_api" "api" {
  name = "orders-api"

  lifecycle {
    create_before_destroy = true
  }
}
```

## Remediation steps
1. Add a `lifecycle` block with `create_before_destroy = true` to the `aws_api_gateway_rest_api` resource.
2. Verify that any custom domain mappings (`aws_api_gateway_base_path_mapping`), deployments, and stages reference the resource via Terraform attribute references (not hardcoded IDs), so dependent resources correctly re-point to the newly created API before the old one is destroyed.
3. Be aware that with `create_before_destroy` enabled, a forced replacement will briefly result in two API Gateway REST APIs coexisting — check for any account-level or naming constraints (e.g. custom domain uniqueness) that could conflict during that window.
4. This is a configuration-only change and does not itself trigger a replacement; it only changes behavior for *future* forced replacements.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayCreateBeforeDestroy.py)
- [Terraform lifecycle meta-argument documentation](https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle)
