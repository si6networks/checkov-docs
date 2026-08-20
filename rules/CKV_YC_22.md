# CKV_YC_22: Ensure compute instance group has security group assigned

## Severity
**HIGH** (score: 7.6/10)

A compute instance group deployed without a security group inherits overly permissive default network access across all instances in the group, broadening the exposed attack surface fleet-wide.

## Summary
This check fails when a Yandex Cloud `yandex_compute_instance_group` resource's instance template network interface does not have `security_group_ids` set.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `yandex_compute_instance_group`

## Why it matters
Instance groups provision and manage a fleet of identical VM replicas (often behind a load balancer or as auto-scaling worker pools). Without an explicit `security_group_ids` set in the group's instance template, every instance the group creates inherits only whatever default/broader network-level rules apply, rather than a purpose-built, least-privilege firewall policy. Because the setting is templated across the entire fleet, the impact of missing network segmentation is multiplied across every replica the group scales to — a single omission results in many under-protected instances rather than just one. This increases exposure to unintended lateral network access from other systems in the same VPC and removes a key layer of defense-in-depth that would otherwise limit which ports/protocols/sources can reach the fleet.

## How Checkov evaluates this
The check (`ComputeInstanceGroupSecurityGroup`) is a `BaseResourceValueCheck` that inspects the attribute path `instance_template/[0]/network_interface/[0]/security_group_ids`:
- The expected value is `ANY_VALUE`.
- If the instance template's first `network_interface` block has `security_group_ids` set (non-empty), the check **PASSES**.
- If absent or empty, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_compute_instance_group" "web_fleet" {
  name               = "web-fleet"
  service_account_id = yandex_iam_service_account.instances.id

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      network_id = yandex_vpc_network.app.id
      subnet_ids = [yandex_vpc_subnet.app.id]
      nat        = false
      # no security_group_ids -- FAILS CKV_YC_22
    }

    resources {
      cores  = 2
      memory = 2
    }

    boot_disk {
      initialize_params {
        image_id = data.yandex_compute_image.ubuntu.id
      }
    }
  }

  scale_policy {
    fixed_scale {
      size = 3
    }
  }

  allocation_policy {
    zones = ["ru-central1-a"]
  }

  deploy_policy {
    max_unavailable = 1
    max_creating    = 1
    max_expansion   = 1
    max_deleting    = 1
  }
}
```

## Remediated example
```hcl
resource "yandex_vpc_security_group" "fleet_sg" {
  name       = "web-fleet-sg"
  network_id = yandex_vpc_network.app.id

  ingress {
    protocol       = "TCP"
    port           = 443
    v4_cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "yandex_compute_instance_group" "web_fleet" {
  name               = "web-fleet"
  service_account_id = yandex_iam_service_account.instances.id

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      network_id         = yandex_vpc_network.app.id
      subnet_ids         = [yandex_vpc_subnet.app.id]
      nat                = false
      security_group_ids = [yandex_vpc_security_group.fleet_sg.id]  # added -- PASSES CKV_YC_22
    }

    resources {
      cores  = 2
      memory = 2
    }

    boot_disk {
      initialize_params {
        image_id = data.yandex_compute_image.ubuntu.id
      }
    }
  }

  scale_policy {
    fixed_scale {
      size = 3
    }
  }

  allocation_policy {
    zones = ["ru-central1-a"]
  }

  deploy_policy {
    max_unavailable = 1
    max_creating    = 1
    max_expansion   = 1
    max_deleting    = 1
  }
}
```

## Remediation steps
1. Create a `yandex_vpc_security_group` scoped to the fleet's actual traffic needs (e.g., only the application port from the load balancer/relevant subnets).
2. Reference it via `security_group_ids` in the instance group's `instance_template.network_interface` block.
3. Avoid depending on default network-level rules for a production fleet — every managed instance should have an explicit, least-privilege security group.
4. This is distinct from CKV_YC_18 (public IP on instance groups); both should be remediated together as part of hardening the group's `network_interface` configuration.
5. Changing the instance template typically triggers a rolling replacement of managed instances — use the group's `deploy_policy` (`max_unavailable`, `max_creating`, etc.) to roll the change out safely.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/ComputeInstanceGroupSecurityGroup.py)
- [Yandex Cloud Instance Groups documentation](https://yandex.cloud/en/docs/compute/concepts/instance-groups/)
