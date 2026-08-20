# CKV_OCI_4: Ensure OCI Compute Instance boot volume has in-transit data encryption enabled

## Severity
**LOW** (score: 2.0/10)

Disabling in-transit encryption for boot volume traffic exposes disk I/O data to interception on the underlying network path between compute and storage.

## Summary
This check ensures that OCI compute instances (`oci_core_instance`) enable in-transit encryption for traffic between the instance and its boot/block volumes.

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_instance`

## Why it matters
By default, data traveling over the network between a compute instance and its remote-attached boot/block storage is not encrypted in transit. On shared physical infrastructure, this exposes disk I/O traffic to interception by anyone with access to the underlying network path (e.g., a compromised hypervisor, a misconfigured network segment, or a malicious co-tenant with unusual levels of access). Enabling in-transit encryption (`is_pv_encryption_in_transit_enabled`) ensures all paravirtualized I/O between the instance and its OCI Block Volume service is protected with encryption, closing this exposure and helping satisfy compliance frameworks that require encryption of data both at rest and in transit.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute `launch_options[0].is_pv_encryption_in_transit_enabled` on `oci_core_instance`. The check passes only if this value is explicitly `true`; any other value (including it being unset, which defaults to `false` for paravirtualized attachments) fails the check.

## Non-compliant example
```hcl
resource "oci_core_instance" "app_server" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  shape               = "VM.Standard.E4.Flex"

  create_vnic_details {
    subnet_id = var.subnet_id
  }

  source_details {
    source_type = "image"
    source_id   = var.image_id
  }

  # launch_options omitted - in-transit encryption not enabled
}
```

## Remediated example
```hcl
resource "oci_core_instance" "app_server" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  shape               = "VM.Standard.E4.Flex"

  create_vnic_details {
    subnet_id = var.subnet_id
  }

  source_details {
    source_type = "image"
    source_id   = var.image_id
  }

  launch_options {
    is_pv_encryption_in_transit_enabled = true
  }
}
```

## Remediation steps
1. Add a `launch_options` block to the `oci_core_instance` resource.
2. Set `is_pv_encryption_in_transit_enabled = true`.
3. Note this setting requires a paravirtualized boot volume attachment type and is only supported on certain shapes/images — confirm your instance shape and image support in-transit encryption before enabling.
4. This attribute is set at launch time; changing it on an existing instance typically requires instance replacement (Terraform will show it as forcing a new resource in most provider versions) — plan for a maintenance window.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/InstanceBootVolumeIntransitEncryption.py)
