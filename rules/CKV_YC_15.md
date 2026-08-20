# CKV_YC_15: Ensure security group is assigned to Kubernetes node group

## Severity
**HIGH** (score: 7.2/10)

Kubernetes worker nodes without an assigned security group are subject to broader-than-intended network reachability, increasing the attack surface against workloads and the node's host-level access.

## Summary
This check fails when a Yandex Managed Service for Kubernetes node group's instance template network interface does not have `security_group_ids` set.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `yandex_kubernetes_node_group`

## Why it matters
Worker nodes run the actual application workloads (pods) and the kubelet/kube-proxy agents that communicate with the control plane. Without a dedicated security group on the node group's network interfaces, node-to-node and inbound network traffic is governed only by broader/default network rules, which can permit unintended lateral access between workloads or from other systems in the same VPC. This weakens network segmentation between the cluster's compute nodes and the rest of the environment, increasing the risk that a compromised host elsewhere in the VPC could directly probe kubelet ports (10250 etc.) or NodePort services, potentially leading to container escape, credential theft (kubelet API, service account tokens), or unauthorized workload access. A dedicated node-group security group lets you restrict traffic to only the necessary cluster-internal communication and legitimate ingress paths (e.g., load balancer health checks).

## How Checkov evaluates this
The check (`K8SNodeGroupSecurityGroup`) is a `BaseResourceValueCheck` that inspects the attribute path `instance_template/[0]/network_interface/[0]/security_group_ids`:
- The expected value is `ANY_VALUE`.
- If the node group's `instance_template.network_interface` block has `security_group_ids` set (non-empty), the check **PASSES**.
- If absent or empty, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_kubernetes_node_group" "workers" {
  cluster_id = yandex_kubernetes_cluster.example.id
  name       = "worker-pool"

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      subnet_ids = [yandex_vpc_subnet.app.id]
      # no security_group_ids -- FAILS CKV_YC_15
    }

    resources {
      cores  = 4
      memory = 8
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
resource "yandex_vpc_security_group" "k8s_nodes_sg" {
  name       = "k8s-nodes-sg"
  network_id = yandex_vpc_network.app.id

  ingress {
    protocol          = "TCP"
    port              = 10250
    predefined_target = "self_security_group"
  }
}

resource "yandex_kubernetes_node_group" "workers" {
  cluster_id = yandex_kubernetes_cluster.example.id
  name       = "worker-pool"

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      subnet_ids         = [yandex_vpc_subnet.app.id]
      security_group_ids = [yandex_vpc_security_group.k8s_nodes_sg.id]  # added -- PASSES CKV_YC_15
    }

    resources {
      cores  = 4
      memory = 8
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
1. Create a `yandex_vpc_security_group` scoped to node-group traffic needs (kubelet ports, intra-cluster pod networking, load-balancer health checks).
2. Attach it via `security_group_ids` in the `instance_template.network_interface` block of the node group.
3. Use `predefined_target = "self_security_group"` rules where appropriate to allow node-to-node cluster traffic without opening the group to the whole VPC.
4. Pair with master-level security groups (CKV_YC_14) and Kubernetes network policies (CKV_YC_16) for layered defense.
5. Note: modifying `instance_template` fields on a node group typically triggers a rolling replacement of nodes — plan for a maintenance window and verify pod disruption budgets are in place.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SNodeGroupSecurityGroup.py)
- [Yandex Managed Service for Kubernetes networking documentation](https://yandex.cloud/en/docs/managed-kubernetes/concepts/networking)
