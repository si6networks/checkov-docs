# CKV_OCI_2: Ensure OCI Block Storage Block Volume has backup enabled

## Severity
**LOW** (score: 2.0/10)

Missing backup policy on a block volume is primarily an availability/data-durability concern rather than a direct confidentiality or integrity attack path.

## Summary
This check verifies that every OCI Block Storage block volume (`oci_core_volume`) is associated with a backup policy, so the volume's data is regularly backed up.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `oci_core_volume`

## Why it matters
Block volumes hold the persistent data for compute instances (databases, application state, file systems). Without an assigned backup policy, there is no scheduled recovery point for the volume: a ransomware event, accidental deletion, corrupted filesystem, or a failed in-place upgrade can result in permanent, unrecoverable data loss. OCI backup policies (Bronze, Silver, Gold, or a custom policy) create scheduled, retained point-in-time backups that let you restore a volume to a prior state. Omitting `backup_policy_id` means the resource silently has no recovery path even though it looks otherwise fully provisioned.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `backup_policy_id` attribute on the `oci_core_volume` resource. The check passes if `backup_policy_id` is set to any non-empty value (`ANY_VALUE`); it fails if the attribute is absent or empty. Checkov does not validate which specific policy is referenced — any assigned policy ID satisfies the check.

## Non-compliant example
```hcl
resource "oci_core_volume" "app_data" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = "app-data-volume"
  size_in_gbs         = 100
  # No backup_policy_id specified - no scheduled backups
}
```

## Remediated example
```hcl
data "oci_core_volume_backup_policies" "gold" {
  filter {
    name   = "display_name"
    values = ["gold"]
  }
}

resource "oci_core_volume" "app_data" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = "app-data-volume"
  size_in_gbs         = 100
  backup_policy_id    = data.oci_core_volume_backup_policies.gold.volume_backup_policies[0].id
}
```

## Remediation steps
1. Decide on a backup cadence and retention (OCI ships built-in Bronze/Silver/Gold policies, or create `oci_core_volume_backup_policy` with custom schedules).
2. Reference the chosen policy's OCID via the `backup_policy_id` attribute on the `oci_core_volume` resource.
3. For existing volumes, this can typically be applied without downtime — it is a metadata association, not a volume replacement.
4. Consider using `oci_core_volume_backup_policy_assignment` as an alternative attachment mechanism if you manage policy assignment separately from the volume resource.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/StorageBlockBackupEnabled.py)
