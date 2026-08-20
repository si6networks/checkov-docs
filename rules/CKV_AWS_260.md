# CKV_AWS_260: Ensure no security groups allow ingress from 0.0.0.0:0 to port 80

## Severity
**MEDIUM** (score: 5.0/10)

Unrestricted ingress on port 80 exposes unencrypted HTTP traffic to the entire internet, which is a real attack-surface and eavesdropping risk for internal/admin services but is frequently an intentional, lower-impact configuration for genuinely public web front ends.

## Summary
This check flags EC2 security groups (or security group rules) that permit unrestricted inbound access (`0.0.0.0/0`, i.e. the entire IPv4 internet) on port 80 (HTTP).

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: resources `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`
- **CloudFormation**: resource types `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`

## Why it matters
Port 80 serves unencrypted HTTP traffic. Leaving it open to `0.0.0.0/0` means any host on the internet can reach the service, which is often acceptable for a public-facing web front end but is frequently misconfigured for internal admin panels, management interfaces, or backend services that should never be internet-reachable. Because HTTP is unencrypted, any traffic that does traverse this port is visible in transit to any network intermediary. Overly broad ingress rules are also the single most common root cause of successful automated internet-wide scanning and exploitation (Shodan-style discovery, credential stuffing, path-traversal, and known CVE exploitation against exposed services). Restricting ingress to specific known CIDR ranges, or to a load balancer's security group, sharply reduces the attack surface; and where HTTP is used, it should generally exist only to redirect to HTTPS.

## How Checkov evaluates this
This check is implemented via a shared base class, `AbsSecurityGroupUnrestrictedIngress`, parameterized with `port=80`. In general, the base check:
- Inspects each ingress rule (in `aws_security_group.ingress`, standalone `aws_security_group_rule` with `type = "ingress"`, `aws_vpc_security_group_ingress_rule`, or CloudFormation `SecurityGroupIngress`/inline ingress blocks).
- Checks whether the rule's `cidr_blocks` (or `CidrIp`) includes `0.0.0.0/0` (or the IPv6 equivalent `::/0` depending on implementation) **and** the rule's port range (`from_port`–`to_port`, or a single `port`/`FromPort`–`ToPort`) includes port 80.
- If a rule matches both unrestricted CIDR and covers port 80, the check **FAILS**; otherwise it **PASSES**.
- Rules restricted to a smaller CIDR block, a security group reference, or a prefix list rather than `0.0.0.0/0` pass.

## Non-compliant example
```hcl
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    description = "HTTP from corporate VPN only"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]   # restrict to known/trusted ranges
  }
}
```
Alternatively, if this is a public web tier meant to redirect HTTP to HTTPS behind a load balancer, restrict the security group to only accept traffic from the load balancer's security group ID rather than a raw CIDR.

## Remediation steps
1. Identify the actual set of clients that need to reach port 80: is it truly public internet, a specific office/VPN CIDR, or another AWS resource (e.g. an ALB)?
2. Replace `cidr_blocks = ["0.0.0.0/0"]` with the narrowest CIDR range that satisfies the requirement, or reference a source security group (`security_groups = [...]`) instead of a CIDR.
3. If the service genuinely needs to be public (e.g., a public website), consider terminating TLS at a load balancer/CDN and redirecting HTTP→HTTPS, and suppress this check with a documented exception (`#checkov:skip=CKV_AWS_260:justification`) rather than silently leaving it flagged.
4. Apply the same review to any `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule` resources that reference the security group, since the check inspects those independently.
5. No resource replacement is required — updating ingress rules is an in-place change, though it may briefly interrupt existing connections from now-blocked sources.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SecurityGroupUnrestrictedIngress80.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/SecurityGroupUnrestrictedIngress80.py
