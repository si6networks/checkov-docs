# CKV_GCP_35: Ensure 'Enable connecting to serial ports' is not enabled for VM Instance

## Severity
**HIGH** (score: 7.5/10)

An enabled interactive serial console provides an alternate, often less-monitored administrative access path to the VM (including during boot) that bypasses normal network/firewall controls, making it a meaningful backdoor if exposed.

## Summary
This check fails when a GCE instance sets `metadata.serial-port-enable = true`, which allows interactive access to the VM's serial console over the network.

## Applicability
**Checkov framework(s):** `terraform`

Terraform only. Applies to `google_compute_instance`, `google_compute_instance_from_template`, and `google_compute_instance_template`.

## Why it matters
The GCE serial console provides a low-level, network-accessible interactive terminal to the instance that operates independently of SSH, firewall rules, and the guest OS's normal network stack — it works even if the VM's network is misconfigured or SSHD is down. Access to the serial port is gated only by IAM permission (`roles/compute.instanceAdmin` or the `compute.instances.getSerialPortOutput`/`use` type roles) and does not require a key pair on the instance, does not go through VPC firewall rules, and is not visible to typical network-based intrusion detection. If serial port access is enabled and the connecting principal's IAM credentials are compromised (or IAM policy is too permissive), an attacker gets a root-equivalent console session that bypasses network segmentation entirely — a materially larger attack surface than SSH under most threat models, especially for internet-facing IAM identities such as CI/CD service accounts.

## How Checkov evaluates this
The check inspects `metadata[0]["serial-port-enable"]`:
- **FAIL** if the value is `True`.
- **PASS** if absent or `False`.
- For `google_compute_instance_from_template`: **UNKNOWN** if `metadata` is missing, or present without a `serial-port-enable` key, since the effective value would come from the referenced template.

## Non-compliant example
```hcl
resource "google_compute_instance" "bastion" {
  name         = "bastion"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  metadata = {
    serial-port-enable = true
  }
}
```

## Remediated example
```hcl
resource "google_compute_instance" "bastion" {
  name         = "bastion"
  machine_type = "e2-small"
  zone         = "us-central1-a"

  boot_disk {
    initialize_from_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = "default"
  }

  metadata = {
    serial-port-enable = false
  }
}
```

## Remediation steps
1. Remove `serial-port-enable = true` from instance/template metadata, or explicitly set it to `false`.
2. If serial console access is genuinely needed for debugging boot failures, enable it only temporarily and scoped to a single instance, then disable it again once troubleshooting is complete.
3. If persistent out-of-band console access is required operationally, restrict who can use it via IAM (`roles/compute.instanceAdmin.v1` grants the underlying permission) and monitor `v2.instances.getSerialPortOutput` / console-connect calls in Cloud Audit Logs.
4. This is a metadata-only change and does not require instance recreation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleComputeSerialPorts.py)
- [GCP: Interacting with the serial console](https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console)
