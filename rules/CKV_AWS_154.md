# CKV_AWS_154: Ensure Redshift is not deployed outside of a VPC
## Severity
**HIGH** (score: 7.5/10)

A Redshift cluster deployed outside a VPC (EC2-Classic) loses the network isolation, security-group boundary, and private-subnet controls that keep the data warehouse from being reachable over the flat, shared EC2-Classic network, materially increasing exposure of the sensitive analytical data it holds.

## Summary
This check verifies that a Redshift cluster is placed inside a VPC (via a cluster subnet group) rather than being launched in the legacy EC2-Classic network mode.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

Terraform (`aws_redshift_cluster`) and CloudFormation (`AWS::Redshift::Cluster`).

## Why it matters
EC2-Classic is AWS's original, deprecated flat networking model that predates VPCs — resources launched there share a single network space across all EC2-Classic customers on the same physical infrastructure, with none of the isolation primitives (private subnets, route tables, security groups scoped to a VPC, NACLs, VPC endpoints, flow logs) that VPCs provide. A Redshift cluster running outside a VPC cannot be placed in a private subnet with no direct internet route, cannot use VPC security groups for fine-grained ingress control, cannot leverage VPC endpoints to keep traffic off the public internet, and cannot participate in typical network segmentation (e.g. isolating the data warehouse tier from public-facing application tiers). Since AWS has been retiring EC2-Classic account-wide, most modern accounts cannot even launch outside a VPC, but Terraform/CloudFormation configurations lacking an explicit subnet group are a signal of legacy or copy-pasted config that should be corrected.

## How Checkov evaluates this
`BaseResourceValueCheck` using `ANY_VALUE` as the expected value: checks whether `cluster_subnet_group_name` (Terraform) / `Properties.ClusterSubnetGroupName` (CloudFormation) is set to *any* non-empty value. If a subnet group is specified (any value) → `PASSED`, meaning the cluster is deployed inside a VPC. If the attribute is absent → `FAILED`, meaning the cluster would be created in EC2-Classic mode (if the account/region still permits it) or otherwise lacks explicit VPC placement.

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier = "analytics-cluster"
  database_name       = "analytics"
  master_username     = "admin"
  master_password     = var.redshift_password
  node_type           = "dc2.large"
  cluster_type        = "single-node"
  # no cluster_subnet_group_name -> not placed in a VPC subnet group
}
```

## Remediated example
```hcl
resource "aws_redshift_subnet_group" "warehouse" {
  name       = "analytics-subnet-group"
  subnet_ids = var.private_subnet_ids
}

resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier        = "analytics-cluster"
  database_name             = "analytics"
  master_username           = "admin"
  master_password           = var.redshift_password
  node_type                 = "dc2.large"
  cluster_type              = "single-node"
  cluster_subnet_group_name = aws_redshift_subnet_group.warehouse.name # <-- added
  vpc_security_group_ids    = [aws_security_group.redshift.id]
}
```

## Remediation steps
1. Create an `aws_redshift_subnet_group` (or `AWS::Redshift::ClusterSubnetGroup`) referencing private subnets in your VPC.
2. Set `cluster_subnet_group_name` (Terraform) / `ClusterSubnetGroupName` (CloudFormation) on the cluster resource.
3. Attach VPC security groups (`vpc_security_group_ids`) scoped to only the clients that need database access.
4. If migrating an existing EC2-Classic cluster, note this typically requires creating a new cluster from a snapshot inside the VPC and cutting over — it cannot be done as an in-place attribute change on a running cluster.
5. Confirm `publicly_accessible` is `false` unless the cluster genuinely needs a public endpoint.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftInEc2ClassicMode.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RedshiftInEc2ClassicMode.py
- AWS docs: https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html
