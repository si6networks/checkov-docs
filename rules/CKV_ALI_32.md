# CKV_ALI_32: Ensure launch template data disks are encrypted
## Severity
**LOW** (score: 2.0/10)

Unencrypted data disks provisioned via a launch template leave persistent VM data readable to anyone with storage/snapshot access, a confidentiality risk across every instance that template creates.

## Summary
This check ensures that any data disks defined inside an Alibaba Cloud ECS launch template are configured with encryption enabled.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `alicloud_ecs_launch_template`

## Why it matters
ECS launch templates define the blueprint that instances (often in Auto Scaling Groups) are created from, including attached data disks. Data stored on unencrypted block storage is readable by anyone with access to the underlying storage medium, snapshots, or a compromised hypervisor/backup pipeline — bypassing OS-level access controls entirely. Because launch templates are reused to spin up many instances at scale, a missing encryption flag here silently propagates the same weakness across every instance created from the template, including databases, caches, and application data volumes that may hold sensitive data. Encryption at rest is also frequently a compliance requirement (e.g., PCI-DSS, ISO 27001) for any storage that may contain regulated data.

## How Checkov evaluates this
This is a custom Python `BaseResourceCheck`. It reads the `data_disks` list attribute from the resource configuration:
- If `data_disks` is present and is a list, the check iterates over each disk block.
- For each disk, if `disk.get('encrypted') != [True]` (i.e., the `encrypted` attribute is missing, `false`, or any value other than `true`), the check **FAILS** and records the specific disk index in `evaluated_keys`.
- If all disks have `encrypted = true`, or if `data_disks` is not defined at all, the check **PASSES**.

## Non-compliant example
```hcl
resource "alicloud_ecs_launch_template" "example" {
  name          = "example-template"
  image_id      = "centos_7_9_x64_20G_alibase_20231221.vhd"
  instance_type = "ecs.g6.large"

  data_disks {
    size       = 100
    category   = "cloud_ssd"
    # "encrypted" not set -> defaults to unencrypted
  }
}
```

## Remediated example
```hcl
resource "alicloud_ecs_launch_template" "example" {
  name          = "example-template"
  image_id      = "centos_7_9_x64_20G_alibase_20231221.vhd"
  instance_type = "ecs.g6.large"

  data_disks {
    size       = 100
    category   = "cloud_ssd"
    encrypted  = true  # <-- added: enables encryption for this data disk
  }
}
```

## Remediation steps
1. Locate every `data_disks` block within affected `alicloud_ecs_launch_template` resources.
2. Add `encrypted = true` to each `data_disks` block.
3. Optionally pair with a `kms_key_id` attribute on the disk block to use a customer-managed key instead of the platform default key, for stricter key-management control.
4. Note: changing `encrypted` on an existing launch template version typically requires creating a new template version rather than modifying instances already launched from the old version in place — plan for a rolling replacement of instances in any associated Auto Scaling Group.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/alicloud/LaunchTemplateDisksAreEncrypted.py)
