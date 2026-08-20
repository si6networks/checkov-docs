# CKV_AWS_198: Ensure no aws_db_security_group resources exist
## Severity
**LOW** (score: 2.0/10)

Legacy EC2-Classic RDS security groups indicate a database running outside a VPC, weakening network isolation and making the instance reachable through a coarser-grained access model than VPC security groups provide.

## Summary
Flags any use of the legacy `aws_db_security_group` resource, since RDS (DB) Security Groups are a deprecated, EC2-Classic-era construct that should not appear in a modern VPC-based RDS deployment.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_db_security_group` — this check unconditionally fails whenever this resource type is present, regardless of configuration.

## Why it matters
RDS DB Security Groups exist solely to control access to RDS instances that were launched outside a VPC (EC2-Classic). Modern RDS deployments live inside a VPC and are secured with standard VPC security groups (`aws_security_group` + `aws_db_subnet_group`). A `aws_db_security_group` resource in your Terraform indicates:
- The database is (or was) running in the legacy EC2-Classic network, which lacks VPC-native isolation features like subnets, route tables, NACLs, and VPC endpoints/PrivateLink.
- The instance cannot take advantage of security features that require VPC placement, such as certain instance classes, enhanced networking, or being placed in a fully private subnet with no path to the internet.
- Continued reliance on an AWS networking model that is being retired, creating operational risk as AWS deprecates EC2-Classic support.

Because there's no way to configure a DB Security Group safely for a modern VPC deployment, Checkov fails on its mere existence.

## How Checkov evaluates this
`RDSHasSecurityGroup` is a `BaseResourceCheck` whose `scan_resource_conf()` unconditionally returns `CheckResult.FAILED` for any `aws_db_security_group` block:

```python
def scan_resource_conf(self, conf):
    # this resource should not exist - RDS Security Groups are for use only
    # when working with an RDS instances outside of a VPC.
    return CheckResult.FAILED
```

## Non-compliant example
```hcl
resource "aws_db_security_group" "legacy_db_sg" {
  name = "legacy-db-sg"

  ingress {
    cidr = "10.0.0.0/24"
  }
}
```

## Remediated example
```hcl
resource "aws_db_subnet_group" "db_subnets" {
  name       = "app-db-subnets"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_security_group" "db_sg" {
  name   = "app-db-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
}

resource "aws_db_instance" "app_db" {
  identifier             = "app-db"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_subnet_group_name   = aws_db_subnet_group.db_subnets.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]  # VPC security group instead
}
```

## Remediation steps
1. Delete the `aws_db_security_group` resource from your configuration.
2. Ensure the RDS instance is deployed into a VPC via `aws_db_subnet_group`.
3. Attach a standard `aws_security_group` to the instance using `vpc_security_group_ids`.
4. Existing EC2-Classic RDS instances generally cannot be migrated in place — plan a snapshot-and-restore into a VPC-based instance, then cut over application connection strings.
5. Validate route tables/NACLs on the new subnets restrict inbound access as tightly as the previous DB security group intended.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSHasSecurityGroup.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
