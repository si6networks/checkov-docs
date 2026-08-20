# CKV_YC_18: Ensure compute instance group does not have public IP

## Severity
**HIGH** (score: 7.7/10)

NAT/public IP on a compute instance group directly exposes every instance in the group to the internet, expanding the externally reachable attack surface across an entire fleet of hosts.

## Summary
This check fails when a Yandex Cloud `yandex_compute_instance_group` resource's instance template network interface has NAT (public IP assignment) enabled.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `yandex_compute_instance_group`

## Why it matters
An instance group typically manages a fleet of auto-scaled compute instances (e.g., backing a load balancer or serving as worker nodes). If `nat = true` is set on the group's instance template, every instance created by the group is provisioned with a public IP address, directly exposing each replica to the internet. This multiplies the attack surface across the entire fleet — rather than a single misconfigured VM, an entire auto-scaling group of instances becomes reachable from the internet, each one a potential target for scanning, brute force, and exploitation. Instances behind a load balancer or serving internal workloads generally have no need for individual public IPs; the load balancer (or a NAT gateway for outbound-only needs) should be the sole internet-facing component.

## How Checkov evaluates this
The check (`ComputeInstanceGroupPublicIP`) is a `BaseResourceNegativeValueCheck` that inspects the attribute path `instance_template/[0]/network_interface/[0]/nat`:
- The forbidden value is `[True]`.
- If `nat` is `true`, the check **FAILS**.
- If `nat` is `false`, unset, or absent, the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_compute_instance_group" "web_fleet" {
  name                = "web-fleet"
  service_account_id  = yandex_iam_service_account.instances.id

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      network_id = yandex_vpc_network.app.id
      subnet_ids = [yandex_vpc_subnet.app.id]
      nat        = true  # every instance gets a public IP -- FAILS CKV_YC_18
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
resource "yandex_compute_instance_group" "web_fleet" {
  name                = "web-fleet"
  service_account_id  = yandex_iam_service_account.instances.id

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      network_id = yandex_vpc_network.app.id
      subnet_ids = [yandex_vpc_subnet.app.id]
      nat        = false  # no public IP -- PASSES CKV_YC_18
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
1. Set `nat = false` (or remove it) on the `instance_template.network_interface` block.
2. Place a Yandex Cloud Network/Application Load Balancer in front of the instance group to handle inbound public traffic and forward it privately to the instances.
3. For outbound-only internet needs (package updates, external API calls), route egress through a NAT gateway/instance rather than individual public IPs.
4. Changing this setting will trigger a rolling replacement of the instance group's managed instances — plan for a gradual rollout using the group's `deploy_policy` to avoid downtime.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/ComputeInstanceGroupPublicIP.py)
- [Yandex Cloud Instance Groups documentation](https://yandex.cloud/en/docs/compute/concepts/instance-groups/)
