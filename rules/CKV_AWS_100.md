# CKV_AWS_100: Ensure AWS EKS node group does not have implicit SSH access from 0.0.0.0/0
## Severity
**HIGH** (score: 7.5/10)

When an EKS node group enables SSH remote access without restricting source security groups, worker nodes become reachable for SSH from the entire internet (0.0.0.0/0), a dangerous management port exposed publicly.

## Summary
This check ensures that EKS managed node groups configured with an SSH key for remote access also restrict that SSH access to specific security groups, rather than implicitly allowing SSH from anywhere on the internet.

## Applicability
- **CloudFormation**: `AWS::EKS::Nodegroup` resources.
- **Terraform**: `aws_eks_node_group` resources.

Specifically the `RemoteAccess`/`remote_access` block's `Ec2SshKey`/`ec2_ssh_key` and `SourceSecurityGroups`/`source_security_group_ids` properties.

## Why it matters
When you configure an EKS managed node group with an SSH key (`ec2_ssh_key`) but do not restrict access via `source_security_group_ids`, EKS creates a security group rule that allows SSH (port 22) from `0.0.0.0/0` — i.e., the entire internet — to every worker node in that node group. Worker nodes typically have IAM instance profiles with permissions to interact with the EKS control plane, pull container images, and access other AWS resources; combined with unrestricted SSH exposure, this creates a direct internet-facing attack surface for credential-stuffing, brute-force, or exploitation of any SSH-related vulnerability. A successful SSH compromise of a node can lead to container/pod escape, theft of the node's IAM credentials via the instance metadata service, and lateral movement into the broader cluster and AWS account.

## How Checkov evaluates this
- **CloudFormation**: if `Properties.RemoteAccess.Ec2SshKey` is set, the check requires `Properties.RemoteAccess.SourceSecurityGroups` to also be present — if it is, **PASS**; if `Ec2SshKey` is set without `SourceSecurityGroups`, **FAIL**. If `RemoteAccess` or `Ec2SshKey` isn't configured at all, the check **PASSES** (no SSH access configured, so nothing to restrict).
- **Terraform**: if `remote_access[0].ec2_ssh_key` is set and `remote_access[0].source_security_group_ids` is **not** present, the check **FAILS**. Otherwise (no SSH key configured, or SSH key configured together with source security groups), the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "workers"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids

  remote_access {
    ec2_ssh_key = aws_key_pair.workers.key_name
    # No source_security_group_ids -> SSH open to 0.0.0.0/0
  }

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
}
```

## Remediated example
```hcl
resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "workers"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids

  remote_access {
    ec2_ssh_key               = aws_key_pair.workers.key_name
    source_security_group_ids = [aws_security_group.bastion_only.id]
  }

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
}
```

## Remediation steps
1. Add `source_security_group_ids` (Terraform) / `SourceSecurityGroups` (CloudFormation) to the `remote_access` block, referencing a security group that only allows SSH from a trusted bastion host or VPN CIDR.
2. Prefer replacing SSH-key-based node access entirely with AWS Systems Manager Session Manager (SSM), which requires no open inbound port and no long-lived SSH key.
3. If SSH access is not actually needed, remove `ec2_ssh_key` from the node group configuration entirely.
4. Note: changing `remote_access` configuration on an existing managed node group typically requires replacing the node group (new node group version/rollout), so plan for a rolling update.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EKSNodeGroupRemoteAccess.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/EKSNodeGroupRemoteAccess.py)
- [AWS EKS managed node groups documentation](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html)
