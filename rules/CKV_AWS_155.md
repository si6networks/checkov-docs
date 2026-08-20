# CKV_AWS_155: Ensure that Workspace user volumes are encrypted
## Severity
**MEDIUM** (score: 5.0/10)

WorkSpaces user volumes hold end-user files and application data; leaving them unencrypted means that data is exposed at rest if the underlying storage is ever accessed outside the normal WorkSpaces access path (e.g. snapshot/volume exfiltration).

## Summary
This check verifies that an Amazon WorkSpaces workspace has its user (D:) volume encryption enabled.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

Terraform (`aws_workspaces_workspace`) and CloudFormation (`AWS::WorkSpaces::Workspace`).

## Why it matters
The user volume on a WorkSpace stores the end user's personal files, documents, downloaded data, browser caches, and application data — often including sensitive business documents, credentials cached by applications, or regulated data (PII, financial records) depending on the organization. If this volume is unencrypted, data at rest on the underlying EBS storage is not protected by KMS: a stolen/improperly decommissioned underlying storage device, an unauthorized EBS snapshot, or gaps in AWS's own physical security controls could expose the raw volume contents. Since WorkSpaces are frequently used for regulated or contractor-facing environments (specifically because they centralize sensitive data away from local laptops), leaving the user volume unencrypted undermines the core security rationale for using WorkSpaces in the first place.

## How Checkov evaluates this
`BaseResourceValueCheck` inspecting `user_volume_encryption_enabled` (Terraform) / `Properties.UserVolumeEncryptionEnabled` (CloudFormation). Terraform version explicitly expects `True`; passes only when the attribute is `true`, fails when `false` or unset.

## Non-compliant example
```hcl
resource "aws_workspaces_workspace" "dev" {
  directory_id = aws_workspaces_directory.main.id
  bundle_id    = data.aws_workspaces_bundle.standard.id
  user_name    = "jdoe"

  workspace_properties {
    running_mode = "AUTO_STOP"
  }
  # user_volume_encryption_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_workspaces_workspace" "dev" {
  directory_id                   = aws_workspaces_directory.main.id
  bundle_id                      = data.aws_workspaces_bundle.standard.id
  user_name                      = "jdoe"
  user_volume_encryption_enabled = true # <-- added
  volume_encryption_key          = "alias/aws/workspaces"

  workspace_properties {
    running_mode = "AUTO_STOP"
  }
}
```

## Remediation steps
1. Set `user_volume_encryption_enabled = true` (Terraform) or `UserVolumeEncryptionEnabled: true` (CloudFormation).
2. Provide a `volume_encryption_key` (KMS key alias or ARN) — the AWS-managed `alias/aws/workspaces` key works out of the box, or supply a customer-managed CMK for tighter control.
3. Note this setting can only be configured at WorkSpace creation time — an existing unencrypted WorkSpace must be rebuilt (terminated and recreated) to enable encryption; it cannot be toggled in place.
4. Pair with `CKV_AWS_156` (root volume encryption) since both volumes should typically be encrypted together.
5. Communicate the rebuild/data-migration impact to end users before remediating existing unencrypted WorkSpaces.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/WorkspaceUserVolumeEncrypted.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/WorkspaceUserVolumeEncrypted.py
- AWS docs: https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html
