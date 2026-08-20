# CKV_YC_16: Ensure network policy is assigned to Kubernetes cluster

## Severity
**MEDIUM** (score: 5.8/10)

Without a Kubernetes network policy provider, pod-to-pod traffic is unrestricted by default, allowing lateral movement between workloads that should otherwise be network-segmented; this is a segmentation gap rather than direct external exposure.

## Summary
This check fails when a Yandex Managed Service for Kubernetes cluster does not configure a `network_policy_provider`, meaning pod-to-pod traffic within the cluster is unrestricted by Kubernetes NetworkPolicy enforcement.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `yandex_kubernetes_cluster`

## Why it matters
By default, Kubernetes allows all pods in a cluster to communicate with all other pods (and often all namespaces) over the pod network, with no built-in isolation. Without a network policy provider (e.g., Calico) enabled at the cluster level, it is impossible to enforce Kubernetes `NetworkPolicy` resources even if application teams try to define them — the CNI simply has no policy engine to act on them. This means that if any single pod/container is compromised (via a vulnerable dependency, SSRF, RCE, etc.), the attacker can freely move laterally to any other pod or service in the cluster, including sensitive internal services, databases-in-cluster, or the Kubernetes API proxy, with no network-level barrier. Enabling a network policy provider is foundational for implementing microsegmentation and a zero-trust posture inside the cluster, limiting the blast radius of any single compromised workload.

## How Checkov evaluates this
The check (`K8SNetworkPolicy`) is a `BaseResourceValueCheck` that inspects the `network_policy_provider` attribute:
- The expected value is `ANY_VALUE`.
- If `network_policy_provider` is set (e.g., to `"CALICO"`), the check **PASSES**.
- If absent, the check **FAILS**.

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
  }
  # no network_policy_provider -- FAILS CKV_YC_16
}
```

## Remediated example
```hcl
resource "yandex_kubernetes_cluster" "example" {
  name                   = "prod-k8s"
  network_id             = yandex_vpc_network.app.id
  network_policy_provider = "CALICO"  # added -- PASSES CKV_YC_16

  master {
    version = "1.28"
    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.app.id
    }
  }
}
```

## Remediation steps
1. Set `network_policy_provider = "CALICO"` on the cluster resource (Calico is the network policy provider currently supported by Yandex Managed Kubernetes).
2. After enabling the provider, define actual Kubernetes `NetworkPolicy` resources in your cluster manifests to enforce default-deny and explicit-allow rules between namespaces/workloads — enabling the provider alone does not restrict traffic until policies are authored.
3. Start with a default-deny-all policy per namespace, then add explicit allow rules for required service-to-service communication.
4. This setting is typically only configurable at cluster creation or may require careful sequencing to enable on an existing cluster — check current Yandex Cloud provider support before applying to a running production cluster, and test policy rollout in a staging cluster first to avoid unintentionally blocking required traffic.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SNetworkPolicy.py)
- [Kubernetes NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
