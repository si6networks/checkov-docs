# CKV_AWS_89: DMS replication instance should not be publicly accessible

## Severity
**CRITICAL** (score: 9.0/10)

A publicly reachable DMS replication instance exposes an endpoint that handles live database migration traffic (often including credentials and sensitive data in transit) to unauthenticated internet access.

## Summary
This check fails when an AWS Database Migration Service (DMS) replication instance has `PubliclyAccessible` (or `publicly_accessible`) set to `true`, exposing the instance to the public internet.

## Applicability
- **Terraform**: `aws_dms_replication_instance` resource — inspects `publicly_accessible`.
- **CloudFormation**: `AWS::DMS::ReplicationInstance` resource — inspects `Properties/PubliclyAccessible`.

## Why it matters
A DMS replication instance sits between source and target databases during migrations or ongoing replication (CDC), and it necessarily holds credentials to both endpoints as well as a live stream of the data being moved — which can include production customer data. A publicly accessible replication instance is directly reachable from the internet, meaning that if its security group is (or ever becomes) misconfigured, an external attacker could attempt to reach the instance's management interface or intercept/interfere with replication traffic. Since these instances often exist temporarily for a migration project and receive less ongoing security scrutiny than long-lived production resources, they are an easy blind spot; keeping them private removes an entire class of exposure regardless of security-group state.

## How Checkov evaluates this
- **Terraform**: `BaseResourceNegativeValueCheck` inspects `publicly_accessible`; the forbidden value is `[True]`. Any resource where this is explicitly `true` fails.
- **CloudFormation**: `BaseResourceValueCheck` inspects `Properties/PubliclyAccessible`; the expected (passing) value is `False`. Anything else fails.

Neither implementation has special-cased exceptions — it's a direct boolean check with no default-value inference.

## Non-compliant example
```hcl
resource "aws_dms_replication_instance" "migration" {
  replication_instance_id   = "migration-instance"
  replication_instance_class = "dms.t3.medium"
  allocated_storage          = 50
  publicly_accessible        = true
}
```

## Remediated example
```hcl
resource "aws_dms_replication_instance" "migration" {
  replication_instance_id     = "migration-instance"
  replication_instance_class  = "dms.t3.medium"
  allocated_storage            = 50
  publicly_accessible          = false
  replication_subnet_group_id = aws_dms_replication_subnet_group.private.id
  vpc_security_group_ids      = [aws_security_group.dms_internal.id]
}
```

## Remediation steps
1. Set `publicly_accessible = false` (Terraform) / `PubliclyAccessible: false` (CloudFormation) explicitly.
2. Place the replication instance in a private subnet group with no route to an internet gateway.
3. If the source or target database is outside the VPC (e.g., on-premises or another cloud), connect via VPN or Direct Connect rather than exposing the DMS instance publicly.
4. Restrict the instance's security group to only the source/target database ports from known CIDR ranges.
5. Tear down or deallocate DMS replication instances promptly after a migration completes — they are often left running longer than necessary.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DMSReplicationInstancePubliclyAccessible.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DMSReplicationInstancePubliclyAccessible.py
- AWS docs: https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.VPC.html
