# CKV_YC_6: Ensure Kubernetes cluster node group does not have public IP addresses.

## Severity
**HIGH** (score: 7.0/10)

Public IPs on Kubernetes node group instances expose worker nodes that run application workloads directly to the internet, broadening the network attack surface against the container runtime and any services bound on the nodes.

## Summary
This check ensures that worker nodes in a Yandex Managed Service for Kubernetes node group are not configured with a public IP / NAT on their network interface, keeping worker nodes reachable only via private networking.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_kubernetes_node_group`
- **Check type:** resource (negative value check)

## Why it matters
Kubernetes worker nodes run the kubelet, container runtime, and application workloads (pods) directly. If a node group's `network_interface` has NAT (public IP) enabled, every node in that group gets a publicly routable address, exposing the kubelet API (which can leak pod logs/exec capabilities if misconfigured), any NodePort services, host-networked pods, and the node's own OS-level attack surface (SSH, package vulnerabilities) directly to the internet. This bypasses cluster-level network policies and ingress controls that are meant to be the sole entry point for external traffic, and it means a single misconfigured NodePort or an unpatched kubelet vulnerability is immediately internet-exploitable rather than requiring lateral movement from inside the VPC. It also increases the blast radius of a compromised node: an attacker with a public entry point to a node can pivot toward the pod network, potentially other workloads, and cloud metadata endpoints. Best practice is for nodes to have only private IPs, with all external traffic funneled through a controlled load balancer / ingress and egress traffic handled via a NAT gateway rather than per-instance public IPs.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the attribute path:
```
instance_template/[0]/network_interface/[0]/nat
```
If `nat` is set to `true` on the node group's instance template network interface, the check **FAILS**. If `nat` is absent, `false`, or any non-`true` value, the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_kubernetes_node_group" "bad_example" {
  cluster_id = yandex_kubernetes_cluster.default.id
  name       = "worker-nodes"
  version    = "1.28"

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      subnet_ids = [yandex_vpc_subnet.default.id]
      nat        = true
    }

    resources {
      memory = 4
      cores  = 2
    }

    boot_disk {
      type = "network-hdd"
      size = 64
    }
  }

  scale_policy {
    fixed_scale {
      size = 3
    }
  }
}
```

## Remediated example
```hcl
resource "yandex_kubernetes_node_group" "good_example" {
  cluster_id = yandex_kubernetes_cluster.default.id
  name       = "worker-nodes"
  version    = "1.28"

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      subnet_ids = [yandex_vpc_subnet.default.id]
      # nat removed / explicitly false — nodes stay on private IPs only
      nat        = false
    }

    resources {
      memory = 4
      cores  = 2
    }

    boot_disk {
      type = "network-hdd"
      size = 64
    }
  }

  scale_policy {
    fixed_scale {
      size = 3
    }
  }
}
```

## Remediation steps
1. Set `nat = false` (or remove the attribute, since `false` is the default) in the node group's `instance_template.network_interface` block.
2. Provision a NAT gateway / NAT instance in the VPC if nodes need outbound internet access (e.g., to pull container images from public registries), rather than assigning each node a public IP.
3. Expose services externally through a load balancer (e.g., `yandex_lb_network_load_balancer`) or ingress controller instead of relying on NodePort/public node IPs.
4. Verify that image pulls, package updates, and any external API calls made by workloads still succeed through the NAT gateway path after this change.
5. Re-run Checkov to confirm `network_interface.nat` is not `true`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SNodeGroupPublicIP.py
