# CKV_AWS_17: Ensure all data stored in RDS is not publicly accessible

## Severity
**CRITICAL** (score: 9.0/10)

A publicly accessible RDS instance exposes a database directly to the internet, making it a prime target for credential-stuffing, brute force, and exploitation of database-engine vulnerabilities against data that is typically highly sensitive.

## Summary
This check requires that RDS database instances are not configured with `publicly_accessible = true`, ensuring the database is only reachable through private networking rather than being assigned a public, internet-routable endpoint.

## Applicability
- **Terraform**: `aws_db_instance`, `aws_rds_cluster_instance`
- **CloudFormation**: `AWS::RDS::DBInstance`

## Why it matters
When an RDS instance is marked publicly accessible, AWS assigns it a publicly resolvable DNS name that resolves to a public IP address, making the database endpoint reachable directly from the internet (subject to security group rules). Databases are high-value targets — they hold the application's core data — and a public endpoint means the only line of defense against internet-wide scanning, credential brute-forcing, and exploitation of database-engine vulnerabilities is the security group configuration and database authentication, both of which are more easily misconfigured or bypassed than simply having no route from the internet at all.

Countless real-world breaches stem from exactly this pattern: an RDS instance made "publicly accessible" temporarily for debugging or by a misunderstanding of Terraform defaults, combined with an overly permissive security group (e.g. `0.0.0.0/0` on port 3306/5432), that goes unnoticed until it's scanned and exploited. Keeping databases non-public forces all access through private networking (VPC, VPN, bastion, or peering), adding a mandatory network-layer barrier before any authentication attempt is even possible.

## How Checkov evaluates this
For CloudFormation, the check inspects `Properties.PubliclyAccessible` on `AWS::RDS::DBInstance`, expecting the value to be `false`; if the property is **absent**, the check explicitly treats that as **PASSED** (CloudFormation's own default for this property is `false`/non-public in most cases the check is scoped to). If present and `true`, it **FAILS**.

For Terraform, the check inspects `publicly_accessible` on `aws_db_instance` / `aws_rds_cluster_instance` and treats `true` as a **forbidden value** — the check **FAILS** if `publicly_accessible = true` is set. If the attribute is omitted, its absence is not flagged as a forbidden value (AWS's own provider default for this attribute is `false`).

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier          = "app-db"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  username            = "appuser"
  password            = "changeme123!"
  publicly_accessible = true
}
```

## Remediated example
```hcl
resource "aws_db_instance" "app_db" {
  identifier          = "app-db"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 20
  username            = "appuser"
  password            = "changeme123!"
  publicly_accessible = false  # changed from true (or simply omit the attribute)
}
```

## Remediation steps
1. Set `publicly_accessible = false` explicitly (or remove the attribute, since `false` is the provider default) on `aws_db_instance`/`aws_rds_cluster_instance` resources, and `PubliclyAccessible: false` in CloudFormation.
2. Ensure the instance is deployed into private subnets (a DB subnet group with no route to an internet gateway) so it has no reachable path from the internet even if a misconfiguration re-enables the flag later.
3. Provide access for legitimate internal/external clients via VPC peering, Transit Gateway, VPN, or a bastion/jump host, rather than a public endpoint.
4. Toggling `publicly_accessible` is applied in-place by AWS (it changes the instance's networking exposure) but can require a brief interruption in some engines/configurations — apply during a maintenance window and verify no clients depend on the public DNS endpoint before flipping it.
5. Audit existing security groups attached to the instance — removing public accessibility does not by itself fix an overly permissive security group; review ingress rules too.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSPubliclyAccessible.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RDSPubliclyAccessible.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
