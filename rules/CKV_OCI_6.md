# CKV_OCI_6: Ensure OCI Compute Instance has monitoring enabled

## Severity
**LOW** (score: 2.0/10)

Disabled compute instance monitoring reduces visibility into resource health and anomalous behavior but does not itself create a direct exploitation path.

## Summary
This check ensures that OCI compute instances (`oci_core_instance`) have the built-in monitoring agent enabled so host metrics are collected.

## Applicability
- **Framework:** Terraform
- **Resource type:** `oci_core_instance`

## Why it matters
Without monitoring enabled, OCI does not collect host-level metrics (CPU, memory, disk, network) for the instance via the OCI Monitoring service. This creates both an operational and a security blind spot: unusual resource consumption patterns (e.g., a cryptomining payload pegging CPU, a data-exfiltration process saturating network egress, or a runaway process consuming memory) go undetected because there's no baseline telemetry to alert against. It also undermines incident response — investigators lose a source of historical performance/behavioral evidence when diagnosing whether an instance was compromised. Monitoring is a foundational control that enables anomaly-detection alarms and supports availability/reliability objectives, not just security ones.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the nested attribute `agent_config[0].is_monitoring_disabled` on `oci_core_instance`. The check fails if this value is explicitly `true` (monitoring disabled). It passes if the attribute is absent (monitoring enabled by default) or explicitly `false`.

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

  agent_config {
    is_monitoring_disabled = true
  }
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

  agent_config {
    is_monitoring_disabled = false
  }
}
```

## Remediation steps
1. Either remove the `agent_config` block entirely (monitoring is enabled by default), or explicitly set `is_monitoring_disabled = false`.
2. Confirm the Oracle Cloud Agent's "Compute Instance Monitoring" plugin is enabled and not disabled elsewhere in `agent_config.plugins_config`.
3. Pair enabled monitoring with alarms (`oci_monitoring_alarm`) on key metrics (CPU utilization, disk I/O, network throughput) to get actionable notifications.
4. This is a non-disruptive, metadata-only change and can be applied via `terraform apply` without instance downtime in most cases.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/InstanceMonitoringEnabled.py)
