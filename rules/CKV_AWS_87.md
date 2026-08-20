# CKV_AWS_87: Redshift cluster should not be publicly accessible

## Severity
**CRITICAL** (score: 9.1/10)

A publicly accessible Redshift cluster exposes a data warehouse endpoint directly to the internet, allowing unauthenticated network reachability to a store of potentially sensitive analytical data.

## Summary
This check fails when an Amazon Redshift cluster is configured with `PubliclyAccessible` (or `publicly_accessible`) set to `true`, which would allow the cluster to receive connections directly from the public internet.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_redshift_cluster` resource — inspects the `publicly_accessible` argument.
- **CloudFormation**: `AWS::Redshift::Cluster` resource — inspects `Properties/PubliclyAccessible`.

## Why it matters
Redshift clusters typically hold large volumes of sensitive analytical/warehouse data — often aggregated from many upstream systems, making them a high-value target. When `PubliclyAccessible` is `true`, AWS assigns the cluster's endpoint a publicly routable IP, and (assuming security group rules also allow it) the cluster's SQL endpoint becomes reachable from any host on the internet, not just from within the VPC. This removes network-layer isolation as a defense and leaves authentication (database credentials, IAM policies) as the only remaining control. Combined with weak passwords, leaked credentials, or brute-force attempts, this significantly raises the risk of unauthorized access to warehouse data, data exfiltration, or a foothold for lateral movement. Best practice is to keep the cluster in a private subnet, reachable only via VPN, bastion, VPC peering, or PrivateLink.

## How Checkov evaluates this
Both implementations are simple attribute-value checks:
- **Terraform**: `BaseResourceValueCheck` inspects the key `publicly_accessible`; the check expects the value `False`. Any other value (including `true` or the attribute being left at its provider default when the default resolves to true) fails.
- **CloudFormation**: `BaseResourceValueCheck` inspects `Properties/PubliclyAccessible`; expected value is `False`.

There is no special-cased exception logic in this check — it is a direct boolean comparison.

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier        = "analytics-cluster"
  database_name              = "analytics"
  master_username            = "admin"
  master_password            = var.redshift_password
  node_type                  = "dc2.large"
  cluster_type                = "single-node"
  publicly_accessible        = true
}
```

## Remediated example
```hcl
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier        = "analytics-cluster"
  database_name              = "analytics"
  master_username            = "admin"
  master_password            = var.redshift_password
  node_type                  = "dc2.large"
  cluster_type                = "single-node"
  publicly_accessible        = false   # only reachable from within the VPC
  cluster_subnet_group_name = aws_redshift_subnet_group.private.name
}
```

## Remediation steps
1. Set `publicly_accessible = false` (Terraform) or `PubliclyAccessible: false` (CloudFormation) explicitly — do not rely on defaults.
2. Place the cluster in a private subnet group with no route to an internet gateway.
3. Provide access via a bastion host, Systems Manager Session Manager port forwarding, Client VPN, or VPC peering/Transit Gateway from trusted networks.
4. If cross-account or partner access to the warehouse is genuinely required, use Redshift data sharing or an internal ALB/NLB fronted by a VPN rather than exposing the cluster endpoint directly.
5. Tighten security group ingress rules on the cluster regardless of this setting — `publicly_accessible=false` alone does not replace proper security-group hygiene.

## References
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RedshiftClusterPubliclyAccessible.py
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshitClusterPubliclyAvailable.py
- AWS docs: https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html
