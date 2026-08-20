# CKV_YC_11: Ensure security group is assigned to network interface

## Severity
**HIGH** (score: 7.3/10)

A compute instance's network interface without an assigned security group falls back to overly permissive default network access, broadening the instance's exposure to unwanted inbound traffic.

## Summary
This check fails when a Yandex Cloud `yandex_compute_instance` resource's network interface does not have a `security_group_ids` attribute set.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `yandex_compute_instance`

## Why it matters
Without an explicit security group on the instance's network interface, network access to the instance is not governed by an application-specific, least-privilege firewall policy. Security groups are the primary stateful-firewall mechanism in Yandex VPC for controlling inbound/outbound traffic at the instance level. Omitting them means the instance may rely solely on broader subnet/network-level rules (or none at all), increasing the risk that unintended ports/services are reachable from other hosts in the network — widening the blast radius if any other system in the same VPC is compromised, and increasing exposure to internal reconnaissance and lateral movement.

## How Checkov evaluates this
The check (`ComputeVMSecurityGroup`) is a `BaseResourceValueCheck` that inspects the attribute path `network_interface/[0]/security_group_ids`:
- The expected value is `ANY_VALUE`.
- If the first `network_interface` block has `security_group_ids` set (non-empty), the check **PASSES**.
- If absent or empty, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_compute_instance" "app" {
  name        = "app-server"
  platform_id = "standard-v3"

  resources {
    cores  = 2
    memory = 4
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.app.id
    nat       = false
    # no security_group_ids -- FAILS CKV_YC_11
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
    }
  }
}
```

## Remediated example
```hcl
resource "yandex_vpc_security_group" "app_sg" {
  name       = "app-instance-sg"
  network_id = yandex_vpc_network.app.id

  ingress {
    protocol       = "TCP"
    port           = 443
    v4_cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_compute_instance" "app" {
  name        = "app-server"
  platform_id = "standard-v3"

  resources {
    cores  = 2
    memory = 4
  }

  network_interface {
    subnet_id          = yandex_vpc_subnet.app.id
    nat                = false
    security_group_ids = [yandex_vpc_security_group.app_sg.id]  # added -- PASSES CKV_YC_11
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
    }
  }
}
```

## Remediation steps
1. Define a `yandex_vpc_security_group` scoped to this instance's actual application needs (only necessary ports/protocols, restricted source CIDRs).
2. Attach it via `security_group_ids` on the instance's `network_interface` block.
3. Avoid relying on network-wide default rules; each workload should have a purpose-built security group.
4. Attaching a security group to an existing instance's network interface can typically be done without a full replacement, but verify with a `terraform plan` since some network interface changes force recreation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/ComputeVMSecurityGroup.py)
- [Yandex Cloud VPC security groups documentation](https://yandex.cloud/en/docs/vpc/concepts/security-groups)
