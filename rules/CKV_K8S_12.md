# CKV_K8S_12: Memory requests should be set
## Severity
**LOW** (score: 2.0/10)

A missing memory request only affects scheduling decisions rather than enforcing a hard cap, so its impact is limited to suboptimal bin-packing rather than a direct exploitable weakness.

## Summary
This check verifies that every container in a Pod-carrying workload declares a memory value under `resources.requests`, so the scheduler has an accurate figure for how much memory the container needs when placing it on a node.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

Two independent implementations cover different IaC surfaces under this ID:
- **Kubernetes** manifests: applicable entity kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet` — evaluated per-container, checking `resources.requests.memory`.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`.

**Important source discrepancy to be aware of:** the Terraform implementation registered under this same ID lives in a file named `MemoryLimits.py` and its class name/title is `"Memory Limits should be set"` — but it is tagged `CKV_K8S_12`, and its actual logic (see below) inspects `resources.limits.memory`, not `resources.requests.memory`. This is an inconsistency in the upstream Checkov codebase between the Kubernetes-native check (which correctly checks `requests.memory` for this ID) and the Terraform check registered under the same ID (which checks `limits.memory`, duplicating the logic of CKV_K8S_13). Treat the **Kubernetes YAML** behavior as the canonical semantic for CKV_K8S_12 ("requests"), and be aware that a Terraform `kubernetes_pod`/`kubernetes_deployment` resource is actually evaluated for a memory *limit* under this ID in current Checkov source.

## Why it matters
`resources.requests.memory` is what the Kubernetes scheduler uses to decide which node has enough capacity to place a Pod, and what kubelet uses to compute a Pod's QoS class. A container with no memory request can be scheduled onto a node without the scheduler accounting for its actual footprint, leading to node-level memory overcommitment: as real usage climbs, the node can run out of memory and the kernel OOM-killer (or kubelet's eviction manager) starts killing Pods — often not the offending one — causing unpredictable, hard-to-diagnose outages. Declaring accurate memory requests is foundational to reliable bin-packing and to Kubernetes' QoS-based eviction ordering (Pods with no requests/limits are BestEffort and are evicted first, but can still destabilize a node before eviction occurs).

## How Checkov evaluates this
**Kubernetes (`MemoryRequests`, a `BaseK8sContainerCheck`):** for each container config, it looks at `resources`. If `resources` is missing, or present but not a dict, or `requests` is missing/not a dict, or `requests.memory` is falsy, the check **FAILS** (or returns `UNKNOWN` for the malformed-type cases). Only when `resources.requests.memory` is present and truthy does it **PASS**.

**Terraform (`MemoryLimits`, registered under `CKV_K8S_12` — see discrepancy note above):** it drills into `spec` (or `spec.template.spec` for Deployment-shaped resources), then iterates `container` blocks. For each container it checks `resources[0].limits[0].memory`; if present it **PASSES**, otherwise it **FAILS** at that container (and, as with CKV_K8S_11's Terraform check, only the first container block is actually evaluated before returning).

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cache
spec:
  containers:
  - name: cache
    image: redis:7
    resources:
      limits:
        memory: "512Mi"
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cache
spec:
  containers:
  - name: cache
    image: redis:7
    resources:
      requests:
        memory: "256Mi"
      limits:
        memory: "512Mi"
```

## Remediation steps
1. Add `resources.requests.memory` to every container spec in Kubernetes-native manifests, based on observed steady-state usage (e.g. from `kubectl top pod` or historical metrics), not a guess.
2. If also managing the workload via Terraform `kubernetes_pod`/`kubernetes_deployment` resources, set `resources.limits.memory` as well, since the current Terraform check under this ID evaluates the limit field rather than the request field (see discrepancy note above) — setting both request and limit satisfies both the Kubernetes-native and Terraform checks and is good practice regardless.
3. Avoid setting the request unrealistically low just to "pass" — an inaccurate request undermines the scheduler's placement decisions just as much as a missing one.
4. Re-run Checkov to confirm both the Kubernetes manifest and any corresponding Terraform resource pass.

## References
- [Checkov Kubernetes check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/MemoryRequests.py)
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/MemoryLimits.py)
- [Kubernetes: Managing Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
