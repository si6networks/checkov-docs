# CKV2_AWS_44: Ensure AWS route table with VPC peering does not contain routes overly permissive to all traffic
## Severity
**HIGH** (score: 7.2/10)

A route table tied to VPC peering with an overly permissive route (0.0.0.0/0 or ::/0) can expose an entire peered VPC's network space rather than the intended peered CIDR range, broadening lateral network reachability.

## Summary
This check fails when a route table (or an individual route) that points at a VPC peering connection also routes the entire `0.0.0.0/0` (or `::/0`) address space through that peering connection, instead of scoping the route to the peer VPC's actual CIDR block.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_route`, `aws_route_table`

## Why it matters
VPC peering is meant to connect two specific address spaces to each other — it should never be able to carry "all internet/all traffic" routing, because a peering connection has no internet gateway or NAT of its own; if a route table sends `0.0.0.0/0` over a peering connection, any traffic not otherwise more-specifically routed (including traffic destined for the internet, other VPCs, or unexpected internal ranges) gets funneled toward the peer VPC. This flattens what should be a narrow, intentional trust boundary between two VPCs into a much larger, unintended one: instances in the peer VPC could receive traffic they were never meant to see, and — depending on peer-side routing/security groups — the peered account could gain a path to intercept or receive traffic intended for entirely unrelated destinations. It also frequently indicates a copy-pasted or overly broad route table meant for an internet gateway/NAT that was mistakenly reused for a peering connection, masking the intended, tightly-scoped VPC-to-VPC route.

## How Checkov evaluates this
This is a graph-based JSON policy combining several `or` branches; overall it **PASSES** if any of the following hold for the route table/route in question:
- The route has no `vpc_peering_connection_id` set at all (`not_exists`), or it's set to an empty string — meaning it isn't a peering route.
- OR (for `aws_route_table`) none of its `route.*.cidr_block` entries contain `0.0.0.0/0` AND none of its `route.*.ipv6_cidr_block` entries contain `::/0` (i.e., the route table has no fully-open route regardless of peering).
- OR (for a standalone `aws_route`) `destination_cidr_block` doesn't contain `0.0.0.0/0` AND `destination_ipv6_cidr_block` doesn't contain `::/0`.
- It **FAILS** when a route/route entry has a non-empty `vpc_peering_connection_id` *and* its destination CIDR is the fully-open `0.0.0.0/0` or `::/0`.

## Non-compliant example
```hcl
resource "aws_vpc_peering_connection" "peer" {
  vpc_id      = aws_vpc.main.id
  peer_vpc_id = aws_vpc.other.id
  auto_accept = true
}

resource "aws_route_table" "bad" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block                = "0.0.0.0/0"
    vpc_peering_connection_id = aws_vpc_peering_connection.peer.id
  }
}
```

## Remediated example
```hcl
resource "aws_vpc_peering_connection" "peer" {
  vpc_id      = aws_vpc.main.id
  peer_vpc_id = aws_vpc.other.id
  auto_accept = true
}

resource "aws_route_table" "good" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block                = aws_vpc.other.cidr_block # scoped to the peer VPC's actual CIDR
    vpc_peering_connection_id = aws_vpc_peering_connection.peer.id
  }
}
```

## Remediation steps
1. Identify every route in the route table that references a `vpc_peering_connection_id`.
2. Replace any `cidr_block`/`destination_cidr_block` of `0.0.0.0/0` (or `ipv6_cidr_block`/`destination_ipv6_cidr_block` of `::/0`) on that route with the specific CIDR range of the peer VPC (or a subset of it, if only some subnets need connectivity).
3. Keep the broad `0.0.0.0/0` route pointed at an internet gateway or NAT gateway target as usual — just don't let it also be the peering route.
4. If multiple peer VPCs share overlapping needs, add one route per peering connection with its own specific destination CIDR rather than one catch-all route.
5. Re-apply and confirm with `aws ec2 describe-route-tables` that the peering route's destination matches the peer VPC's CIDR, not `0.0.0.0/0`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/VPCPeeringRouteTableOverlyPermissive.json
- AWS docs: https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html
