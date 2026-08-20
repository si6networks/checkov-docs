# CKV_AWS_217: Ensure Create before destroy for API deployments
## Severity
**LOW** (score: 2.0/10)

This check governs Terraform's create_before_destroy lifecycle ordering for API Gateway deployments, which affects deployment reliability and downtime, not confidentiality, integrity, or an exploitable attack surface.

## Summary
This check ensures that an `aws_api_gateway_deployment` resource enables the `create_before_destroy` lifecycle setting, so that redeployments create the new deployment before destroying the old one.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_api_gateway_deployment`

## Why it matters
This is primarily a reliability/availability check rather than a confidentiality/integrity one. API Gateway deployments are immutable snapshots that stages point to; by default, Terraform's plan/apply cycle for many resources destroys the old resource before creating the replacement. For `aws_api_gateway_deployment`, if the old deployment is destroyed first while a stage still references it, AWS returns an error such as `BadRequestException: Active stages pointing to this deployment must be moved or deleted` — the apply fails mid-way, potentially leaving the API Gateway stage without a valid deployment, causing an outage for API consumers until manually repaired. Beyond just failing the apply, an interrupted or partially-applied change to a production API can leave stale/incorrect routing in place, which is itself a security-relevant availability and integrity concern (e.g. a stage temporarily serving an old, vulnerable deployment version, or serving no traffic and causing dependent systems to fail open/closed unpredictably).

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested lifecycle attribute path `lifecycle/[0]/create_before_destroy`:
- If `lifecycle { create_before_destroy = true }` is set on the resource, the check **PASSES**.
- If the lifecycle block is missing, or `create_before_destroy` is `false`/absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.example.body))
  }
}
```

## Remediated example
```hcl
resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.example.body))
  }

  lifecycle {
    create_before_destroy = true
  }
}
```

## Remediation steps
1. Add a `lifecycle { create_before_destroy = true }` block to the `aws_api_gateway_deployment` resource.
2. Ensure a `triggers` map (commonly a hash of the REST API body/config) is present so Terraform correctly detects when a new deployment is needed, since `create_before_destroy` alone doesn't force redeployment on API changes.
3. Confirm any `aws_api_gateway_stage` resources reference the deployment via `deployment_id` so Terraform can correctly sequence the create-then-repoint-then-destroy operations.
4. Re-run Checkov and `terraform plan` to confirm the resource passes and future redeployments won't error.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/APIGatewayDeploymentCreateBeforeDestroy.py)
- [Terraform AWS Provider: aws_api_gateway_deployment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_deployment)
