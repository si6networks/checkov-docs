# CKV2_AWS_35: AWS NAT Gateways should be utilized for the default route
## Severity
**LOW** (score: 2.0/10)

Routing default traffic through a self-managed NAT instance instead of the managed NAT Gateway increases attack surface and blast radius (an unpatched, internet-adjacent host handling all outbound traffic) but requires a separate compromise of that instance to be exploited.

## Summary
This check flags route tables whose default route (`0.0.0.0/0`) is pointed at an EC2 instance acting as a NAT (via `instance_id`) instead of a managed `aws_nat_gateway`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_route_table` (inline `route` blocks), `aws_route` (standalone route resources)
- **Category:** Networking

## Why it matters
Using a self-managed EC2 instance as a NAT instance for outbound internet access from private subnets is both a reliability and security anti-pattern. Unlike the AWS-managed NAT Gateway service — which is fully managed, automatically scales to handle bandwidth, and is deployed redundantly within an Availability Zone — a NAT instance is a single EC2 host that must have `source_dest_check` disabled, requires you to patch and harden its OS yourself, becomes a single point of failure with no automatic failover, and represents an additional attack surface (a general-purpose, internet-adjacent instance with elevated network privileges routing all outbound traffic from your private subnets). If that instance is compromised, an attacker gains a foothold with visibility into all outbound traffic from every private-subnet resource routed through it — a much larger blast radius than a fully managed NAT Gateway, which AWS operates and patches with no customer-accessible OS. NAT instances also commonly get left running with default/weak security group rules or unpatched AMIs since they are easy to "set and forget."

## How Checkov evaluates this
This is a graph check (`AWSNATGatewaysshouldbeutilized.json`) expressed as an `or` of PASS conditions — i.e., the route table/route passes if ANY of these hold:
- The `aws_route_table`'s `route.*.instance_id` attribute does not exist (no inline NAT-instance route), OR
- That `instance_id` attribute is an empty string, OR
- The route table's `route.*.cidr_block` does not contain `0.0.0.0/0` (i.e., there's no default route at all in this table, so the NAT-instance concern doesn't apply), OR
- For standalone `aws_route` resources: `instance_id` does not exist, OR it's an empty string, OR the route's `destination_cidr_block` does not contain `0.0.0.0/0`.

In short: the check only fails when a route table or route resource defines a default route (`0.0.0.0/0`) whose target is explicitly an `instance_id` (an EC2 instance), rather than a `nat_gateway_id`, `gateway_id`, `transit_gateway_id`, etc.

## Non-compliant example
```hcl
resource "aws_instance" "nat_instance" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  source_dest_check      = false
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block  = "0.0.0.0/0"
    instance_id = aws_instance.nat_instance.id
  }
}
```

## Remediated example
```hcl
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
}
```

## Remediation steps
1. Provision an `aws_nat_gateway` in a public subnet with an associated `aws_eip` for its allocation.
2. Update the private subnet's route table's default route (`0.0.0.0/0`) to target `nat_gateway_id = aws_nat_gateway.main.id` instead of `instance_id`.
3. Decommission the EC2 NAT instance once traffic has cutover — verify no dependent security group rules or monitoring reference it before deleting.
4. For high availability across multiple Availability Zones, provision one NAT Gateway per AZ (each with its own EIP) and route each AZ's private subnets to the NAT Gateway in the same AZ, rather than a single shared NAT Gateway across AZs.
5. Caveat: NAT Gateway incurs an hourly charge plus per-GB data processing charges, which is typically still lower total cost of ownership than an EC2 instance once you factor in patching/ops overhead and the reliability difference — but budget for the line-item change if migrating from a NAT instance.
6. This change may briefly interrupt outbound connectivity for resources in the affected private subnets during cutover; plan for a maintenance window if the workload is sensitive to a short network blip.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AWSNATGatewaysshouldbeutilized.json)
- [AWS NAT Gateway documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html)
