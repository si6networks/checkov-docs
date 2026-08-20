# CKV_K8S_13: Memory limits should be set
## Severity
**LOW** (score: 2.0/10)

Omitting a memory limit lets a container consume unbounded memory and trigger node-level OOM conditions, creating an availability risk for co-located workloads rather than a confidentiality or integrity breach.

## Summary
This check verifies that every container in a Pod-carrying workload declares a memory value under `resources.limits`, so a container cannot consume unbounded memory on its node.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

Two independent implementations cover different IaC surfaces under this ID:
- **Kubernetes** manifests: applicable entity kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet` — evaluated per-container, checking `resources.limits.memory`.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`.

**Important source discrepancy to be aware of:** the Terraform implementation registered under this ID lives in a file named `MemoryRequests.py`, and its class name/title is `"Memory requests should be set"` — but it is tagged `CKV_K8S_13`, and its actual logic (see below) inspects `resources.requests.memory`, not `resources.limits.memory`. This mirrors the inverse mix-up documented under CKV_K8S_12: in current upstream Checkov source, the Terraform check registered as CKV_K8S_13 actually validates a memory *request*, while the Kubernetes-native check registered as CKV_K8S_13 validates a memory *limit*. Treat the **Kubernetes YAML** behavior as canonical for CKV_K8S_13 ("limits").

## Why it matters
Without a memory limit, a container is free to consume memory up to the node's total capacity. Because memory is not a compressible resource the way CPU is, when a node runs low the kernel's OOM-killer intervenes — and it does not necessarily kill the offending container; it can kill any process on the node, including unrelated Pods' containers or even critical node-level agents, based on OOM scoring heuristics. A single unbounded container (due to a memory leak, an unexpected traffic spike, or malicious activity) can therefore destabilize every workload co-located on that node. Memory limits are also required for a Pod to receive the `Guaranteed` QoS class (when limits equal requests), which affects eviction priority under node memory pressure.

## How Checkov evaluates this
**Kubernetes (`MemoryLimits`, a `BaseK8sContainerCheck`):** for each container config, it looks at `resources`. If `resources` is missing, or present but not a dict, the check returns `UNKNOWN` for the malformed case, or **FAILS** if `limits`/`limits.memory` is absent. Only when `resources.limits.memory` is present and truthy does it **PASS**.

**Terraform (`MemoryRequests`, registered under `CKV_K8S_13` — see discrepancy note above):** it drills into `spec` (or `spec.template.spec` for Deployment-shaped resources), then iterates `container` blocks. For each container it checks `resources[0].requests[0].memory`; if present it **PASSES**, otherwise **FAILS** at that container (and, like the other Terraform Kubernetes checks in this family, only evaluates the first container block before returning).

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  serviceName: db
  replicas: 1
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
      - name: db
        image: postgres:16
        resources:
          requests:
            memory: "512Mi"
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  serviceName: db
  replicas: 1
  selector:
    matchLabels:
      app: db
  template:
    metadata:
      labels:
        app: db
    spec:
      containers:
      - name: db
        image: postgres:16
        resources:
          requests:
            memory: "512Mi"
          limits:
            memory: "1Gi"
```

## Remediation steps
1. Add `resources.limits.memory` to every container spec in Kubernetes-native manifests, sized with headroom above expected peak usage (memory limits, unlike CPU, cause an OOMKill rather than throttling if exceeded, so size generously but not unboundedly).
2. If also managing the workload via Terraform `kubernetes_pod`/`kubernetes_deployment` resources, set `resources.requests.memory` as well, since the current Terraform check under this ID evaluates the request field rather than the limit field (see discrepancy note above) — setting both satisfies both checks and is best practice regardless.
3. For Guaranteed QoS on latency- or reliability-sensitive workloads, set `limits.memory` equal to `requests.memory`.
4. Monitor for OOMKilled events (`kubectl describe pod` / `kubectl get events`) after rollout to confirm the chosen limit isn't too tight before enforcing it broadly.
5. Re-run Checkov to confirm the resource now passes.

## References
- [Checkov Kubernetes check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/MemoryLimits.py)
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/MemoryRequests.py)
- [Kubernetes: Managing Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
