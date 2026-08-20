# CKV_YC_14: Ensure security group is assigned to Kubernetes cluster

## Severity
**HIGH** (score: 7.6/10)

A Kubernetes cluster's master/control-plane endpoint left without a security group is exposed to overly permissive default network rules, increasing the risk of unauthorized access to the cluster API.

## Summary
This check fails when a Yandex Managed Service for Kubernetes cluster's master does not have `security_group_ids` set.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `yandex_kubernetes_cluster`

## Why it matters
The Kubernetes control plane (API server, etcd, scheduler, controller-manager) is the most privileged component of a cluster — anyone who can reach the API server with valid credentials effectively controls the cluster's workloads, secrets, and configuration. Without a dedicated security group locking down the master's network interfaces, the control plane's network exposure depends on default/broader network rules, which may permit access from a wider set of sources than intended. This increases the risk of unauthorized network-level access attempts against the API server (credential stuffing, exploitation of any exposed management ports, or reconnaissance) from other systems within the same VPC or, in misconfigured environments, the internet. A dedicated security group lets you restrict control-plane network reachability to only the specific administrative subnets, CI/CD systems, or bastion hosts that legitimately need API server access.

## How Checkov evaluates this
The check (`K8SSecurityGroup`) is a `BaseResourceValueCheck` that inspects the attribute path `master/[0]/security_group_ids`:
- The expected value is `ANY_VALUE`.
- If the cluster's `master` block has `security_group_ids` set (non-empty), the check **PASSES**.
- If absent or empty, the check **FAILS**.

## Non-compliant example
```hcl
resource "yandex_kubernetes_cluster" "example" {
  name       = "prod-k8s"
  network_id = yandex_vpc_network.app.id

  master {
    version = "1.28"
    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.app.id
    }
    # no security_group_ids -- FAILS CKV_YC_14
  }
}
```

## Remediated example
```hcl
resource "yandex_vpc_security_group" "k8s_master_sg" {
  name       = "k8s-master-sg"
  network_id = yandex_vpc_network.app.id

  ingress {
    protocol       = "TCP"
    port           = 6443
    v4_cidr_blocks = ["10.0.10.0/24"]  # admin/CI subnet only
  }
}

resource "yandex_kubernetes_cluster" "example" {
  name       = "prod-k8s"
  network_id = yandex_vpc_network.app.id

  master {
    version = "1.28"
    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.app.id
    }
    security_group_ids = [yandex_vpc_security_group.k8s_master_sg.id]  # added -- PASSES CKV_YC_14
  }
}
```

## Remediation steps
1. Create a `yandex_vpc_security_group` allowing only the necessary ingress to the Kubernetes API port (typically 6443) from known administrative/CI subnets.
2. Attach it via `security_group_ids` in the cluster's `master` block.
3. Also review and restrict egress rules as needed for cluster component communication requirements.
4. Combine with node-group-level security groups (CKV_YC_15) and network policy (CKV_YC_16) for defense-in-depth.
5. Changing security groups on the master may be applied in-place in most cases, but verify the current Yandex Cloud provider's behavior with `terraform plan` before applying to production.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SSecurityGroup.py)
- [Yandex Managed Service for Kubernetes networking documentation](https://yandex.cloud/en/docs/managed-kubernetes/concepts/networking)
