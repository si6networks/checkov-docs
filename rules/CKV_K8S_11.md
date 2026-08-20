# CKV_K8S_11: CPU limits should be set
## Severity
**LOW** (score: 2.0/10)

Omitting CPU limits allows a container to consume unbounded CPU on a node, enabling noisy-neighbor resource exhaustion that degrades or denies service to co-located workloads.

## Summary
This check verifies that every container in a Pod-carrying workload declares a CPU `limits` value under `resources`, so a container cannot consume unbounded CPU on its node.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

Two independent implementations cover different IaC surfaces under the same ID:
- **Kubernetes** manifests: applicable entity kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet` — evaluated per-container.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1` — evaluated per-container inside `spec.container` (or `spec.template.spec.container` for Deployments).

## Why it matters
A container without a CPU limit can consume all available CPU on its node during a spike (a runaway process, an infinite loop, a traffic surge, or a compromised/malicious workload performing crypto-mining or similar abuse). Because Kubernetes' CPU is a compressible resource, an unbounded container throttles or starves every other Pod scheduled on that node, degrading cluster-wide performance and potentially causing cascading failures or missed liveness/readiness deadlines in unrelated workloads. Setting CPU limits is a foundational multi-tenancy and reliability control — it bounds the "noisy neighbor" problem and makes QoS class assignment (Guaranteed/Burstable) predictable for cluster capacity planning and autoscaling.

## How Checkov evaluates this
**Kubernetes (`CPULimits`, a `BaseK8sContainerCheck`):** for each container config, it looks at `resources`. If `resources` is missing entirely, or is present but has no `limits.cpu` value, the check **FAILS**. If `resources` exists but is not a dict, it returns `UNKNOWN`. Only when `resources.limits.cpu` is present and truthy does it **PASS**.

**Terraform (`CPULimits`, a `BaseResourceCheck`):** it drills into `spec` (or `spec.template.spec` for Deployment-shaped resources), then iterates each `container` block. For each container it checks `resources[0].limits[0].cpu`; if present it **PASSES**. If `resources` or `limits` block is missing it **FAILS** at that container (note: the Terraform implementation returns on the *first* container evaluated rather than iterating all containers to completion, so only the first container block is actually checked in a multi-container resource).

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.25
        resources:
          requests:
            cpu: "100m"
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.25
        resources:
          requests:
            cpu: "100m"
          limits:
            cpu: "500m"
```

Terraform equivalent:
```hcl
resource "kubernetes_deployment_v1" "web" {
  metadata {
    name = "web"
  }
  spec {
    template {
      spec {
        container {
          name  = "web"
          image = "nginx:1.25"
          resources {
            requests = {
              cpu = "100m"
            }
            limits = {
              cpu = "500m"   # added
            }
          }
        }
      }
    }
  }
}
```

## Remediation steps
1. Add a `resources.limits.cpu` field to every container spec, sized based on observed usage (`kubectl top pod` or metrics-server data) plus headroom, not an arbitrary guess.
2. Avoid setting the limit far above the request — a large gap makes the node's actual available capacity unpredictable under load (overcommit risk).
3. For latency-sensitive workloads, consider setting `limits.cpu` equal to `requests.cpu` to get the Guaranteed QoS class and avoid CPU throttling entirely; for bursty workloads a proportionally larger limit is fine.
4. If using a `LimitRange` in the namespace to enforce a default, note that Checkov evaluates the workload's own manifest and generally does not resolve cluster-side `LimitRange` defaults — set the limit explicitly in the manifest to satisfy the check.
5. Re-run Checkov (`checkov -f <file>` or `-d <dir>`) to confirm the resource now passes.

## References
- [Checkov Kubernetes check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/CPULimits.py)
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/CPULimits.py)
- [Kubernetes: Managing Resources for Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
