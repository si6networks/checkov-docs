# CKV_YC_4: Ensure compute instance does not have serial console enabled.

## Severity
**HIGH** (score: 8.0/10)

Enabling the serial console on a compute instance opens an out-of-band, network-boundary-bypassing interactive access path to the VM that operates outside normal SSH/firewall controls, giving an attacker with cloud-account access a direct route to the instance's console.

## Summary
This check ensures Yandex Cloud Compute instances do not have the serial port/console enabled via instance metadata, since an enabled serial console provides an additional, less-monitored access path into the VM.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `yandex_compute_instance`
- **Check type:** resource (negative value check)

## Why it matters
The serial console gives direct, out-of-band access to a VM's console — bypassing normal network-based access controls such as security groups, SSH key-based authentication flows, and VPC network boundaries. If `serial-port-enable` is set on instance metadata, anyone with the appropriate Yandex Cloud IAM permission (e.g., `compute.instances.get`/serial port access, not necessarily network access to the VM) can attach to the instance's console, which may allow interacting with an unauthenticated boot prompt, bootloader, recovery shell, or a root console session, especially if the instance's OS is configured to spawn a getty/login shell on the serial line. This significantly expands the attack surface: an over-privileged IAM principal, a compromised cloud-console session, or an insider with only IAM access (no VPC network path) could gain interactive access to the instance without needing to compromise SSH keys or traverse the network layer at all. It also undermines network segmentation and firewall controls designed to restrict who can reach a given instance, and can bypass audit logging that would normally capture SSH-based logins.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the attribute path:
```
metadata/[0]/serial-port-enable
```
If this metadata key is set to `true`, the check **FAILS**. If the key is absent or set to `false` (or any value other than `true`), the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_compute_instance" "bad_example" {
  name        = "app-server"
  platform_id = "standard-v3"

  resources {
    cores  = 2
    memory = 4
  }

  boot_disk {
    initialize_params {
      image_id = "fd8xxxxxxxxxxxxxxxxx"
    }
  }

  network_interface {
    subnet_id = "e9bxxxxxxxxxxxxxxxxx"
    nat       = true
  }

  metadata = {
    "serial-port-enable" = "1"
  }
}
```

## Remediated example
```hcl
resource "yandex_compute_instance" "good_example" {
  name        = "app-server"
  platform_id = "standard-v3"

  resources {
    cores  = 2
    memory = 4
  }

  boot_disk {
    initialize_params {
      image_id = "fd8xxxxxxxxxxxxxxxxx"
    }
  }

  network_interface {
    subnet_id = "e9bxxxxxxxxxxxxxxxxx"
    nat       = true
  }

  # serial-port-enable removed/omitted so console access is disabled
  metadata = {
    "ssh-keys" = "ubuntu:${file("~/.ssh/id_ed25519.pub")}"
  }
}
```

## Remediation steps
1. Remove the `serial-port-enable` key from the instance's `metadata` block entirely, or explicitly set it to `"0"`/`false`.
2. If serial console access is genuinely needed for break-glass troubleshooting, enable it temporarily and only for the specific instance/session needed, then disable it again afterward — do not leave it permanently enabled in IaC.
3. Restrict the IAM role/permission that grants serial port access (`compute.instances.get` combined with the relevant serial-port permission) to a small, audited set of operators.
4. Prefer standard SSH-based access with key-based authentication and security-group-restricted network access for routine administration.
5. Re-run Checkov to confirm the metadata no longer sets `serial-port-enable` to a truthy value.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/ComputeVMSerialConsole.py
