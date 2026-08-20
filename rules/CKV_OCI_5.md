# CKV_OCI_5: Ensure OCI Compute Instance has Legacy MetaData service endpoint disabled

## Severity
**MEDIUM** (score: 5.0/10)

Leaving the legacy (v1) instance metadata service enabled removes IMDSv2-style protections and increases susceptibility to SSRF-based credential theft from the metadata endpoint, a well-documented cloud attack technique.

## Summary
This check ensures that OCI compute instances (`oci_core_instance`) disable the legacy (v1) Instance Metadata Service (IMDS) endpoint, forcing use of the more secure v2 endpoint only.

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_instance`

## Why it matters
The legacy IMDS v1 endpoint does not require a session token/header on requests, making it vulnerable to Server-Side Request Forgery (SSRF) attacks: if an application running on the instance has an SSRF vulnerability (e.g., a proxy that fetches arbitrary URLs, an image-fetching library, or an unvalidated redirect), an attacker can trick the instance into making an unauthenticated `GET` request to the metadata endpoint and retrieve sensitive instance data — including attached IAM/instance-principal credentials, user_data (which often contains bootstrap secrets), and instance identity information. This is analogous to the AWS IMDSv1 SSRF class of vulnerabilities (e.g., the Capital One breach). Disabling legacy IMDS endpoints and requiring the newer, token-based access pattern significantly raises the bar for an attacker to exploit an SSRF bug into full credential theft.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the nested attribute `instance_options[0].are_legacy_imds_endpoints_disabled` on `oci_core_instance`. The check passes only if this value is explicitly `true`. If the attribute is absent (legacy endpoints remain enabled by default) or set to `false`, the check fails.

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

  # instance_options omitted - legacy IMDS v1 endpoint remains enabled
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

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }
}
```

## Remediation steps
1. Add an `instance_options` block to the `oci_core_instance` resource with `are_legacy_imds_endpoints_disabled = true`.
2. Before rolling this out broadly, verify that all software running on the instance (agents, cloud-init scripts, monitoring tools) uses the IMDS v2 request pattern (with the required `Authorization: Bearer Oracle` header) — code that only speaks the legacy unauthenticated protocol will break.
3. This is generally applied at instance launch; changing it on an existing instance may require instance replacement depending on the provider version.
4. Pair this with least-privilege instance principal/dynamic group policies so that even if metadata is somehow reached, the exposed credentials have minimal blast radius.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/InstanceMetadataServiceEnabled.py)
