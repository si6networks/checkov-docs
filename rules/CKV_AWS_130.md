# CKV_AWS_130: Ensure VPC subnets do not assign public IP by default

## Severity
**HIGH** (score: 7.0/10)

Subnets that auto-assign public IPs cause instances launched into them to default to internet-reachable addresses, materially increasing the chance of unintentionally exposing workloads to the public internet.

## Summary
This check requires that `aws_subnet` resources do not set `map_public_ip_on_launch = true`, preventing instances launched into the subnet from automatically receiving a public IP address.

## Applicability
- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_subnet`

## Why it matters
When `map_public_ip_on_launch` is true, every EC2 instance launched into that subnet gets a public IPv4 address by default — even if the developer launching it didn't intend for it to be internet-reachable. This is a common root cause of accidental exposure: a database, internal service, or test instance ends up directly reachable from the internet, bypassing the intended network segmentation between public (DMZ) and private tiers. Combined with an overly permissive security group, this can turn what was meant to be an internal-only resource into an internet-facing attack surface — a frequent finding in real-world breaches (e.g., improperly exposed management interfaces, databases, or internal APIs). Explicit, per-instance opt-in to a public IP is safer than a subnet-wide default.

## How Checkov evaluates this
The check (`BaseResourceNegativeValueCheck`) treats `True` as a *forbidden* value for the `map_public_ip_on_launch` key:
- **FAIL** if `map_public_ip_on_launch = true` is explicitly set.
- **PASS** if the attribute is `false`, or not set at all (the negative-value-check base class treats a missing key as passing since the forbidden value isn't present).

## Non-compliant example
```hcl
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true   # FAIL: instances get public IPs by default
}
```

## Remediated example
```hcl
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false  # PASS: no implicit public IP assignment
}

# Public-facing instances instead attach an Elastic IP or explicit public IP
# on the aws_instance/aws_network_interface resource itself, e.g.:
resource "aws_instance" "bastion" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = true   # explicit, resource-level opt-in
}
```

## Remediation steps
1. Set `map_public_ip_on_launch = false` on every `aws_subnet` (this is also the AWS API default for subnets not marked public at creation).
2. For instances that genuinely need a public IP, set `associate_public_ip_address = true` explicitly on the `aws_instance` resource, or attach an `aws_eip`.
3. Re-architect truly public-facing workloads to sit behind a load balancer or NAT/bastion rather than exposing individual instance public IPs where possible.
4. This is a subnet-level attribute; disabling it does not require replacing the subnet and does not affect instances already running (it only affects future launches).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SubnetPublicIP.py)
- [AWS: IP addressing for your VPCs and subnets](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html)
