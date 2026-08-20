# CKV_YC_7: Ensure Kubernetes cluster auto-upgrade is enabled.

## Severity
**MEDIUM** (score: 5.0/10)

Disabling auto-upgrade on the Kubernetes cluster control plane means known security patches for the Kubernetes version are not applied automatically, gradually increasing exposure to disclosed CVEs rather than creating an immediate exploitable gap.

## Summary
This check ensures that the Yandex Managed Service for Kubernetes cluster master has auto-upgrade enabled in its maintenance policy, so the control plane automatically receives security and stability patches.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_kubernetes_cluster`
- **Check type:** resource (negative value check)

## Why it matters
Kubernetes control-plane components (API server, scheduler, controller-manager, etcd) regularly receive security patches for CVEs affecting authentication, authorization, admission control, and the API surface. If auto-upgrade is disabled, the cluster master version is effectively frozen until an operator manually triggers an upgrade — a step that is often deprioritized, forgotten, or delayed due to fear of breaking changes. This leaves the cluster running known-vulnerable Kubernetes versions for extended periods, an attractive target since exploit code for disclosed Kubernetes CVEs is often public and cluster version is easy to fingerprint. Falling significantly behind on Kubernetes versions also risks losing vendor support, and forces large, riskier multi-version jumps later instead of small, incremental, well-tested upgrades. Auto-upgrade (combined with a sensible maintenance window) ensures the control plane stays current with security fixes on a predictable, low-risk cadence managed by the cloud provider.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the attribute path:
```
master/[0]/maintenance_policy/[0]/auto_upgrade
```
If `auto_upgrade` is explicitly set to `false`, the check **FAILS**. If it is `true`, or the attribute/block is not set (Yandex Cloud's default is auto-upgrade enabled), the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_kubernetes_cluster" "bad_example" {
  name       = "prod-cluster"
  network_id = yandex_vpc_network.default.id

  master {
    version = "1.28"

    maintenance_policy {
      auto_upgrade = false
      auto_repair  = true
    }

    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.default.id
    }
  }

  service_account_id      = yandex_iam_service_account.k8s.id
  node_service_account_id = yandex_iam_service_account.k8s_node.id
}
```

## Remediated example
```hcl
resource "yandex_kubernetes_cluster" "good_example" {
  name       = "prod-cluster"
  network_id = yandex_vpc_network.default.id

  master {
    version = "1.28"

    maintenance_policy {
      # auto_upgrade enabled so security patches are applied automatically
      auto_upgrade = true
      auto_repair  = true

      maintenance_window {
        start_time = "22:00"
        duration   = "3h"
      }
    }

    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.default.id
    }
  }

  service_account_id      = yandex_iam_service_account.k8s.id
  node_service_account_id = yandex_iam_service_account.k8s_node.id
}
```

## Remediation steps
1. Set `auto_upgrade = true` in the `master.maintenance_policy` block (or remove the block entirely to accept the provider default, then verify the default is indeed enabled for your provider version).
2. Define a `maintenance_window` (day/time) within a low-traffic period so upgrades happen predictably rather than at arbitrary times.
3. Ensure workloads are resilient to brief control-plane maintenance (this affects the API server, not running pods, but API-dependent automation like CI/CD or autoscalers should tolerate brief API unavailability).
4. Monitor Yandex Cloud's release notes/changelog for the Kubernetes versions your cluster may be upgraded to, so application compatibility issues are caught proactively rather than by surprise.
5. Re-run Checkov to confirm `maintenance_policy.auto_upgrade` is not `false`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SAutoUpgrade.py
