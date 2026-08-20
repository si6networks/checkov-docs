# CKV_AWS_331: Ensure Transit Gateways do not automatically accept VPC attachment requests
## Severity
**HIGH** (score: 7.0/10)

Auto-accepting Transit Gateway VPC attachment requests removes the approval gate for new network peers, allowing any VPC (including ones outside the intended trust boundary) to attach and route traffic into the shared network without review.

## Summary
This check requires that `aws_ec2_transit_gateway` resources do not set `auto_accept_shared_attachments = "enable"`, so that VPC attachment requests from other accounts must be manually reviewed and approved rather than auto-accepted.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_ec2_transit_gateway`

## Why it matters
A Transit Gateway is a central network hub that can interconnect many VPCs, VPNs, and Direct Connect links, often spanning multiple AWS accounts via Resource Access Manager (RAM) sharing. If `auto_accept_shared_attachments` is enabled, any account that the Transit Gateway is shared with can attach its own VPC without any approval step from the network/security team that owns the gateway. This effectively lets another account unilaterally add a network path into your shared transit infrastructure — potentially connecting an untrusted, compromised, or simply out-of-scope VPC directly into your core network without review, bypassing the intended chokepoint for reviewing new network connections. Requiring manual acceptance preserves an approval gate and audit trail before any new network path is established.

## How Checkov evaluates this
The check (`Ec2TransitGatewayAutoAccept.py`) extends `BaseResourceNegativeValueCheck`:
- It inspects `auto_accept_shared_attachments`.
- The forbidden value is `"enable"` — if set to `enable`, the check **FAILS**.
- If set to `"disable"` (the AWS default) or omitted, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_ec2_transit_gateway" "bad_example" {
  description                     = "Shared transit gateway"
  auto_accept_shared_attachments  = "enable"
}
```

## Remediated example
```hcl
resource "aws_ec2_transit_gateway" "good_example" {
  description                    = "Shared transit gateway"
  auto_accept_shared_attachments = "disable"
}
```

## Remediation steps
1. Set `auto_accept_shared_attachments` to `"disable"` (or simply omit it, since that's the AWS default).
2. Establish a manual review/approval workflow (e.g., via a runbook, ticketing process, or automation that inspects the requesting account/VPC CIDR before accepting) for attachment requests using `aws_ec2_transit_gateway_vpc_attachment_accepter` or the console/CLI accept action.
3. If broad, low-risk sharing to trusted internal accounts is genuinely intended (e.g., in a tightly controlled AWS Organization with SCPs), document the exception and consider scoping via RAM resource shares to only the specific trusted accounts, rather than relying on this bypass at the gateway level.
4. This attribute can be changed in place without recreating the Transit Gateway or its existing attachments.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/Ec2TransitGatewayAutoAccept.py)
- [AWS: Transit Gateway attachments](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-vpc-attachments.html)
