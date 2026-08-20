# CKV_AWS_156: Ensure that Workspace root volumes are encrypted
## Severity
**MEDIUM** (score: 5.0/10)

WorkSpaces root volumes contain the OS image plus locally cached credentials, configuration, and application data; without encryption at rest, that volume's contents are exposed if the underlying storage is accessed outside the normal desktop session.

## Summary
This check verifies that an Amazon WorkSpaces workspace has its root (C:) volume encryption enabled.

## Applicability
Terraform (`aws_workspaces_workspace`) and CloudFormation (`AWS::WorkSpaces::Workspace`).

## Why it matters
The root volume of a WorkSpace holds the operating system, installed applications, and often OS-level caches, registry hives, temp files, and application configuration that can contain credentials, tokens, or fragments of sensitive data even though the "user" data is nominally on the separate user volume. Leaving the root volume unencrypted means data-at-rest protections are inconsistent across the two volumes attached to the same virtual desktop, and any exposure route affecting underlying storage (improper snapshot handling, decommissioned hardware, account compromise leading to unauthorized snapshot copies) can expose OS-level secrets even if the user volume is separately encrypted. Consistent encryption of both volumes is required to make a defensible claim that a WorkSpace fully protects data at rest.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting `root_volume_encryption_enabled` (Terraform) / `Properties.RootVolumeEncryptionEnabled` (CloudFormation). Terraform version explicitly expects `True`; passes only when set to `true`, fails when `false` or unset.

## Non-compliant example
```hcl
resource "aws_workspaces_workspace" "dev" {
  directory_id = aws_workspaces_directory.main.id
  bundle_id    = data.aws_workspaces_bundle.standard.id
  user_name    = "jdoe"

  workspace_properties {
    running_mode = "AUTO_STOP"
  }
  # root_volume_encryption_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_workspaces_workspace" "dev" {
  directory_id                   = aws_workspaces_directory.main.id
  bundle_id                      = data.aws_workspaces_bundle.standard.id
  user_name                      = "jdoe"
  root_volume_encryption_enabled = true # <-- added
  volume_encryption_key          = "alias/aws/workspaces"

  workspace_properties {
    running_mode = "AUTO_STOP"
  }
}
```

## Remediation steps
1. Set `root_volume_encryption_enabled = true` (Terraform) or `RootVolumeEncryptionEnabled: true` (CloudFormation).
2. Provide `volume_encryption_key` — either the AWS-managed `alias/aws/workspaces` key or a customer-managed CMK.
3. This can only be set at WorkSpace creation time; an existing unencrypted WorkSpace requires termination and recreation to enable it — plan for user data migration and downtime.
4. Always set this alongside `user_volume_encryption_enabled` (`CKV_AWS_155`) so both volumes on the same desktop are encrypted consistently.
5. If deploying via a WorkSpaces bundle/directory at scale, bake these settings into your standard provisioning template so new WorkSpaces are compliant by default.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/WorkspaceRootVolumeEncrypted.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/WorkspaceRootVolumeEncrypted.py
- AWS docs: https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html
