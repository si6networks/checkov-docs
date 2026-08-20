# CKV_YC_2: Ensure compute instance does not have public IP

## Severity
**HIGH** (score: 7.5/10)

Assigning a public IP (NAT) to a compute instance exposes it directly to the internet, removing the network isolation that would otherwise require traversal through a controlled gateway or bastion.

## Summary
This check fails when a Yandex Cloud `yandex_compute_instance` resource has NAT (public IP assignment) enabled on one of its network interfaces.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `yandex_compute_instance`

## Why it matters
Assigning a public IP directly to a compute instance exposes it to the entire internet, making it a direct target for automated port scanning, brute-force SSH/RDP attempts, and exploitation of any unpatched services running on it. Instances that only need to communicate within a VPC (or reach the internet outbound via a NAT gateway) do not need an inbound-reachable public address. Keeping compute instances private and routing any necessary external access through a bastion host, load balancer, or NAT gateway significantly reduces the attack surface and centralizes where perimeter security controls (firewalls, IDS/IPS, logging) are applied.

## How Checkov evaluates this
The check (`ComputeVMPublicIP`) is a `BaseResourceNegativeValueCheck` that inspects the attribute path `network_interface/[0]/nat` (the `nat` field of the first `network_interface` block):
- The forbidden value is `[True]`.
- If `nat` is set to `true`, the check **FAILS** (a public IP is being requested).
- If `nat` is `false`, unset, or the instance has no such configuration, the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_compute_instance" "web" {
  name        = "web-server"
  platform_id = "standard-v3"

  resources {
    cores  = 2
    memory = 2
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.app.id
    nat       = true  # public IP assigned -- FAILS CKV_YC_2
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
resource "yandex_compute_instance" "web" {
  name        = "web-server"
  platform_id = "standard-v3"

  resources {
    cores  = 2
    memory = 2
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.app.id
    nat       = false  # no public IP -- PASSES CKV_YC_2
  }

  boot_disk {
    initialize_params {
      image_id = data.yandex_compute_image.ubuntu.id
    }
  }
}
```

## Remediation steps
1. Set `nat = false` (or remove the `nat` attribute entirely) on each `network_interface` block of the instance.
2. If the instance needs outbound internet access (e.g., to pull packages or call external APIs), route it through a NAT gateway/NAT instance instead of assigning a direct public IP.
3. If inbound access from the internet is genuinely required (e.g., a public web server), place the instance behind a Yandex Cloud Application/Network Load Balancer, which terminates public traffic and forwards it privately, rather than exposing the instance directly.
4. For administrative access, use a bastion host or Yandex Cloud's session manager/IAP-style tooling rather than a direct public IP + SSH.
5. Changing `nat` on an existing instance's network interface typically requires the instance to be stopped or replaced — plan for a maintenance window.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/ComputeVMPublicIP.py)
- [Yandex Cloud VPC documentation](https://yandex.cloud/en/docs/vpc/concepts/address)
