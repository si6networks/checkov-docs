# CKV_AWS_97: Ensure Encryption in transit is enabled for EFS volumes in ECS Task definitions

## Severity
**HIGH** (score: 7.5/10)

Disabling in-transit encryption for EFS volumes mounted into ECS tasks allows filesystem traffic between task and volume to be intercepted on the network path, though it requires network-level positioning to exploit.

## Summary
This check fails when an ECS task definition mounts an EFS volume without setting `TransitEncryption`/`transit_encryption` to `ENABLED` on the `EFSVolumeConfiguration`, leaving traffic between the ECS task and the EFS file system unencrypted.

## Applicability
- **Terraform**: `aws_ecs_task_definition` resource — inspects each `volume[].efs_volume_configuration[].transit_encryption`.
- **CloudFormation**: `AWS::ECS::TaskDefinition` resource — inspects each `Properties.Volumes[].EFSVolumeConfiguration.TransitEncryption`.

## Why it matters
When an ECS task mounts an Amazon EFS volume, the NFS traffic between the container and the EFS mount targets normally traverses the VPC network. Without transit encryption, that NFS traffic — which can include full file contents, file metadata, and possibly sensitive application data (uploads, shared configuration, logs) — is sent in plaintext over the network. Any entity with visibility into the VPC network path (a compromised host on the same subnet, a misconfigured mirroring/monitoring setup, or an attacker who has gained a foothold elsewhere in the VPC) could passively capture that traffic. Enabling `TransitEncryption` wraps the NFS traffic in TLS, which is a low-cost mitigation given EFS already supports it natively via `efs-utils`/the ECS-managed mount helper — there's rarely a legitimate reason to leave it disabled.

## How Checkov evaluates this
- **Terraform**: Iterates `volume` blocks; for each one containing `efs_volume_configuration`, checks whether `transit_encryption == ["ENABLED"]`. If found → PASSED; if the `efs_volume_configuration` block exists but transit_encryption is not `ENABLED` → FAILED. If no `volume` block is defined at all → PASSED (nothing to encrypt).
- **CloudFormation**: Same logic over `Properties.Volumes[].EFSVolumeConfiguration`: if found and `TransitEncryption == "ENABLED"` → PASSED; if the EFS config exists but this isn't set to `ENABLED` → FAILED. If there are no volumes, or no EFS-backed volume among them → PASSED.

Note: the check stops at the first volume it evaluates for CloudFormation (returns immediately per volume rather than continuing to check all volumes), so with multiple EFS volumes only the first one encountered determines the overall result in that implementation.

## Non-compliant example
```hcl
resource "aws_ecs_task_definition" "app" {
  family                   = "app-task"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                        = "256"
  memory                     = "512"

  volume {
    name = "shared-data"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.data.id
      # transit_encryption not set -> defaults to disabled
    }
  }

  container_definitions = jsonencode([{
    name  = "app"
    image = "myrepo/app:1.0"
  }])
}
```

## Remediated example
```hcl
resource "aws_ecs_task_definition" "app" {
  family                   = "app-task"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                        = "256"
  memory                     = "512"

  volume {
    name = "shared-data"
    efs_volume_configuration {
      file_system_id           = aws_efs_file_system.data.id
      transit_encryption        = "ENABLED"
      transit_encryption_port  = 2999
    }
  }

  container_definitions = jsonencode([{
    name  = "app"
    image = "myrepo/app:1.0"
  }])
}
```

## Remediation steps
1. Add `transit_encryption = "ENABLED"` to every `efs_volume_configuration` block in the task definition (Terraform), or `TransitEncryption: ENABLED` under `EFSVolumeConfiguration` (CloudFormation).
2. Optionally pin `transit_encryption_port` to a specific port if your security groups/NACLs require a known port for the encrypted NFS tunnel.
3. If using EFS access points (`authorization_config`), transit encryption is generally required alongside IAM authorization for the mount to succeed — verify both are set together.
4. No downtime is required — this is set at task-definition level and takes effect on new task deployments; existing running tasks are unaffected until replaced.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECSTaskDefinitionEFSVolumeEncryption.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ECSTaskDefinitionEFSVolumeEncryption.py
- AWS docs: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/efs-volumes.html
