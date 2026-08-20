# CKV_AWS_131: Ensure that ALB drops HTTP headers

## Severity
**MEDIUM** (score: 5.0/10)

Without dropping invalid HTTP headers, an ALB can be desynchronized from backend targets, enabling request smuggling, cache poisoning, or WAF-bypass attacks against a public-facing entry point.

## Summary
This check requires Application Load Balancers to enable `drop_invalid_header_fields` (Terraform) / `routing.http.drop_invalid_header_fields.enabled` (CloudFormation) so the ALB rejects HTTP requests containing invalid header fields before forwarding them to backend targets.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Frameworks:** Terraform (AWS provider), CloudFormation
- **Resource types:**
  - Terraform: `aws_lb`, `aws_alb` (only when `load_balancer_type` is not `"gateway"` or `"network"` — those return UNKNOWN since the setting doesn't apply to NLB/GWLB)
  - CloudFormation: `AWS::ElasticLoadBalancingV2::LoadBalancer` (only evaluated when the load balancer `Type` is `application` or unspecified, since `application` is the default type; non-ALB types return UNKNOWN)

## Why it matters
HTTP header injection and request smuggling attacks often rely on malformed or invalid HTTP header fields (unusual characters, malformed folding, duplicate/conflicting headers) to confuse the load balancer and backend server into interpreting the same request differently. This discrepancy can be exploited for request smuggling, cache poisoning, or bypassing security controls (like WAF rules) that only inspect the "outer" request as parsed by the load balancer. Enabling `drop_invalid_header_fields` causes the ALB to reject such malformed requests outright (returning an HTTP 400) instead of passing ambiguous headers through to the application, closing off a known class of desync attacks between the load balancer and origin.

## How Checkov evaluates this
**Terraform** (`ALBDropHttpHeaders`, based on `BaseResourceValueCheck`):
- If `load_balancer_type` is `["gateway"]` or `["network"]`, the result is **UNKNOWN** (setting is inapplicable to NLB/GWLB).
- Otherwise, it inspects the `drop_invalid_header_fields` attribute: **PASS** if `true`, **FAIL** if `false` or absent.

**CloudFormation** (`ALBDropHttpHeaders`, based on `BaseResourceCheck`):
- Determines if the load balancer is an ALB: `Type` property must be `"application"` or unset (ALB is the default type).
- If not an ALB (e.g., `network` or `gateway`), result is **UNKNOWN**.
- If it is an ALB, it looks through the `LoadBalancerAttributes` list for a `Key` of `routing.http.drop_invalid_header_fields.enabled`.
- **PASS** if that key's `Value` is (case-insensitively, including boolean `True`) the string `"true"`.
- **FAIL** if the key is absent, or its value is anything other than `"true"`.

## Non-compliant example
```hcl
resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  # drop_invalid_header_fields not set -> defaults to false -> FAIL
}
```

```yaml
Resources:
  AppALB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: application
      Subnets: !Ref PublicSubnetIds
      # LoadBalancerAttributes missing drop_invalid_header_fields.enabled -> FAIL
```

## Remediated example
```hcl
resource "aws_lb" "app" {
  name                       = "app-alb"
  internal                   = false
  load_balancer_type         = "application"
  subnets                    = var.public_subnet_ids
  drop_invalid_header_fields = true   # added
}
```

```yaml
Resources:
  AppALB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: application
      Subnets: !Ref PublicSubnetIds
      LoadBalancerAttributes:
        - Key: routing.http.drop_invalid_header_fields.enabled
          Value: "true"   # added
```

## Remediation steps
1. For Terraform ALBs, add `drop_invalid_header_fields = true` to the `aws_lb`/`aws_alb` resource.
2. For CloudFormation, add a `LoadBalancerAttributes` entry with `Key: routing.http.drop_invalid_header_fields.enabled` and `Value: "true"`.
3. Confirm `load_balancer_type`/`Type` is `application` — this setting has no effect (and Checkov marks it UNKNOWN) on Network or Gateway Load Balancers, so it does not apply there.
4. Test with any legacy clients that send non-standard but functionally required headers, as this setting will cause the ALB to reject requests with invalid header fields (HTTP 400) rather than passing them through.
5. This is a load-balancer attribute update applied in place with no downtime or replacement required.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ALBDropHttpHeaders.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ALBDropHttpHeaders.py)
- [AWS: Application load balancer attributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes)
