# CKV_YC_8: Ensure Kubernetes node group auto-upgrade is enabled.

## Severity
**MEDIUM** (score: 5.0/10)

Disabling auto-upgrade on Kubernetes worker node groups leaves node OS and kubelet components unpatched over time, increasing the window during which known vulnerabilities in node components remain exploitable.

## Summary
This check ensures that Yandex Managed Service for Kubernetes node groups have auto-upgrade enabled in their maintenance policy, so worker node OS/kubelet versions are kept automatically patched.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_kubernetes_node_group`
- **Check type:** resource (negative value check)

## Why it matters
Worker nodes run the kubelet, container runtime, and the underlying host OS that hosts every pod in the cluster. Unpatched nodes can carry known vulnerabilities in the kubelet (privilege escalation, container escape vectors), the container runtime (e.g., runc CVEs enabling host breakout), and the OS kernel/packages. If node-group auto-upgrade is disabled, nodes can silently drift far behind the cluster's control-plane version and behind available security patches, since node upgrades are frequently a "someday" task deferred by operators. A version-skewed or stale node pool increases risk of both security vulnerabilities being exploited and Kubernetes version-skew compatibility problems between the control plane and kubelet (Kubernetes only supports the kubelet being up to a few minor versions behind the API server). Auto-upgrade, applied within a defined maintenance window, keeps nodes rolling forward safely and predictably rather than requiring manual intervention that's easy to neglect.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the attribute path:
```
maintenance_policy/[0]/auto_upgrade
```
If `auto_upgrade` is explicitly set to `false`, the check **FAILS**. If it is `true` or the `maintenance_policy`/`auto_upgrade` attribute is not set (relying on the provider default), the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_kubernetes_node_group" "bad_example" {
  cluster_id = yandex_kubernetes_cluster.default.id
  name       = "worker-nodes"
  version    = "1.28"

  maintenance_policy {
    auto_upgrade = false
    auto_repair  = true
  }

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      subnet_ids = [yandex_vpc_subnet.default.id]
      nat        = false
    }

    resources {
      memory = 4
      cores  = 2
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

  maintenance_policy {
    # auto_upgrade enabled so nodes receive kubelet/OS security patches
    auto_upgrade = true
    auto_repair  = true

    maintenance_window {
      start_time = "22:00"
      duration   = "3h"
    }
  }

  instance_template {
    platform_id = "standard-v3"

    network_interface {
      subnet_ids = [yandex_vpc_subnet.default.id]
      nat        = false
    }

    resources {
      memory = 4
      cores  = 2
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
1. Set `auto_upgrade = true` in the node group's `maintenance_policy` block (or omit the block to accept the provider default, after confirming that default is enabled).
2. Define a `maintenance_window` during low-traffic hours to control when node upgrades/replacements roll out.
3. Ensure workloads scheduled on this node group tolerate rolling node replacement (PodDisruptionBudgets, sufficient replica counts, graceful termination handling) since node auto-upgrade typically involves draining and replacing nodes.
4. Combine with `auto_repair = true` so unhealthy nodes are also automatically replaced.
5. Re-run Checkov to confirm `maintenance_policy.auto_upgrade` is not `false`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SNodeGroupAutoUpgrade.py
