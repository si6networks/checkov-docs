# CKV_AWS_321: Ensure Redshift clusters use enhanced VPC routing

## Severity
**MEDIUM** (score: 5.0/10)

Without enhanced VPC routing, Redshift COPY/UNLOAD traffic can traverse the public internet instead of staying within the VPC, weakening network segmentation for data movement.

## Summary
This check ensures Amazon Redshift clusters have `enhanced_vpc_routing` enabled, forcing all COPY/UNLOAD/data-import traffic to route through the cluster's VPC instead of over the public internet.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_redshift_cluster`

## Why it matters
Without enhanced VPC routing, Redshift routes network traffic for `COPY`, `UNLOAD`, `CREATE EXTERNAL SCHEMA` (Redshift Spectrum), and cross-region data transfer operations through the public internet rather than through your VPC. This means traffic carrying potentially sensitive data being loaded into or unloaded from the warehouse bypasses VPC-level controls entirely: VPC security groups, network ACLs, VPC Flow Logs for traffic monitoring, and any traffic-inspection or DLP appliances deployed in the VPC. That traffic becomes invisible to your network monitoring and uninspectable, and depending on network topology could traverse less-trusted paths. Enabling enhanced VPC routing forces this traffic through the VPC (using VPC endpoints for S3, DynamoDB, etc., and a NAT gateway/instance for other destinations), letting you enforce network segmentation, egress control, and traffic logging consistently. This aligns with boundary-protection controls (NIST 800-53 SC-7, SC-7(4), SC-7(9), SC-7(11)).

## How Checkov evaluates this
A `BaseResourceValueCheck` with `missing_block_result = CheckResult.FAILED`, inspecting `enhanced_vpc_routing`:
- **FAIL** if the attribute is missing or `false`.
- **PASS** if `enhanced_vpc_routing = true`.

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier  = "example-cluster"
  node_type            = "dc2.large"
  cluster_type         = "single-node"
  master_username      = "admin"
  master_password      = var.redshift_password
  database_name        = "app_analytics_db"
  # enhanced_vpc_routing not set -> COPY/UNLOAD traffic can traverse the public internet
}
```

## Remediated example
```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier      = "example-cluster"
  node_type                = "dc2.large"
  cluster_type             = "single-node"
  master_username          = "admin"
  master_password          = var.redshift_password
  database_name            = "app_analytics_db"
  enhanced_vpc_routing     = true             # forces COPY/UNLOAD traffic through the VPC
  cluster_subnet_group_name = aws_redshift_subnet_group.example.name
}
```

## Remediation steps
1. Set `enhanced_vpc_routing = true` on the `aws_redshift_cluster` resource.
2. Ensure the cluster is deployed inside a VPC with a subnet group (`cluster_subnet_group_name`) — enhanced VPC routing requires the cluster not be in EC2-Classic and to have appropriate subnet/route table configuration.
3. Create VPC endpoints for Amazon S3 (and DynamoDB, if used for COPY/UNLOAD) so this traffic doesn't need a NAT gateway/internet route at all.
4. For destinations outside AWS (or without a VPC endpoint), ensure a NAT gateway or NAT instance and appropriate route tables exist so COPY/UNLOAD to those destinations continues to work.
5. Test existing ETL/COPY/UNLOAD jobs after enabling this — DNS resolution and connectivity requirements change, and jobs without a valid VPC egress path will start failing.
6. This can typically be modified in-place via `ModifyCluster`, though it may briefly interrupt in-flight COPY/UNLOAD operations.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterUseEnhancedVPCRouting.py
- AWS docs: https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html
