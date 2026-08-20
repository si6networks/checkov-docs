# CKV_AWS_123: Ensure that VPC Endpoint Service is configured for Manual Acceptance

## Severity
**LOW** (score: 2.0/10)

Without manual acceptance required, any principal that discovers the VPC Endpoint Service can establish a connection to the exposed service without explicit approval, an access-control gap on private connectivity rather than full public exposure.

## Summary
Fails when a VPC Endpoint Service (used to expose a service via AWS PrivateLink) does not require the service owner to manually accept new connection requests from consumer VPCs.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_vpc_endpoint_service` resource.
- **CloudFormation**: `AWS::EC2::VPCEndpointService`.

## Why it matters
A VPC Endpoint Service lets other AWS accounts/VPCs connect to a service you host via AWS PrivateLink, without traffic traversing the public internet. The `acceptance_required` setting controls whether new endpoint connection requests from consumer VPCs are automatically accepted or must be manually approved by the service provider:
- If `acceptance_required = false`, **any** principal who can discover the endpoint service name (and who is permitted per the service's allowed-principals list, if configured) can establish a private network connection to your service without any manual review — effectively an automatic-trust model.
- If the allowed-principals list is also broad or misconfigured, this compounds into unreviewed, potentially unauthorized network paths being established to internal services.
- Manual acceptance (`acceptance_required = true`) adds a human-in-the-loop control point: every new connection request must be explicitly approved by the service owner, providing an opportunity to verify the requester is legitimate before any private connectivity is established — a meaningful control against unauthorized lateral network access between accounts/VPCs, especially in multi-account or partner-facing architectures.

## How Checkov evaluates this
A `BaseResourceValueCheck` inspecting the `acceptance_required` (Terraform) / `AcceptanceRequired` (CloudFormation) attribute:
- **PASS** if the value is truthy (`true`).
- **FAIL** if the value is `false` or unset (AWS's default for `acceptance_required` is actually `true` on creation via the API, but if explicitly set to `false` or omitted in a way the check's base class interprets as failing, it flags this).

## Non-compliant example
```hcl
resource "aws_vpc_endpoint_service" "bad" {
  acceptance_required        = false
  network_load_balancer_arns = [aws_lb.internal_service.arn]
}
```

## Remediated example
```hcl
resource "aws_vpc_endpoint_service" "good" {
  acceptance_required        = true
  network_load_balancer_arns = [aws_lb.internal_service.arn]
}

resource "aws_vpc_endpoint_service_allowed_principal" "consumer" {
  vpc_endpoint_service_id = aws_vpc_endpoint_service.good.id
  principal_arn            = "arn:aws:iam::210987654321:root"
}
```

## Remediation steps
1. Set `acceptance_required = true` on the `aws_vpc_endpoint_service` resource.
2. Maintain (or add) an explicit allowed-principals list (`aws_vpc_endpoint_service_allowed_principal`) restricting which AWS accounts/principals are even permitted to request a connection in the first place — manual acceptance is a second layer of defense, not a replacement for principal allowlisting.
3. Establish an operational process for reviewing and approving/rejecting pending endpoint connection requests (via `aws ec2 accept-vpc-endpoint-connections` / console) so the manual-acceptance control isn't just a rubber stamp with no actual review criteria.
4. This setting can be changed on an existing endpoint service without replacement; existing already-accepted connections are unaffected — the setting only governs future connection requests.
5. Document the approval criteria (e.g. required change-ticket reference, requester identity verification) so the manual step provides real security value rather than becoming a bottleneck that gets rubber-stamped.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/VPCEndpointAcceptanceConfigured.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/VPCEndpointAcceptanceConfigured.py
- AWS documentation: https://docs.aws.amazon.com/vpc/latest/privatelink/create-endpoint-service.html
