# CKV_K8S_10: CPU requests should be set
## Severity
**LOW** (score: 2.0/10)

Missing CPU requests only affects scheduler fairness and workload availability (resource starvation/noisy-neighbor effects), not confidentiality or integrity.

## Summary
This check ensures every container in a Kubernetes workload has a CPU `requests` value set under `resources`, so the scheduler knows how much CPU capacity to reserve for it.

## Applicability
Applies to Kubernetes manifests (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) and Terraform configurations using the `kubernetes` provider (`kubernetes_deployment`, `kubernetes_deployment_v1`, `kubernetes_pod`, `kubernetes_pod_v1`), evaluated per-container.

## Why it matters
Without a CPU request, the Kubernetes scheduler has no reservation to base placement decisions on for that container, and the container is treated as "BestEffort" or "Burstable" (depending on whether limits are set) for CPU scheduling purposes. In practice this leads to two related failure modes: (1) the scheduler can over-pack a node with workloads whose real CPU needs were never declared, causing severe CPU contention/throttling once traffic increases, and (2) under node CPU pressure, pods without CPU requests set are treated as lower priority for scheduling fairness and are among the first candidates evicted or throttled, causing unpredictable latency spikes or outages for workloads that "looked fine" in testing but were never actually guaranteed any CPU share. This directly undermines cluster capacity planning, autoscaling (Horizontal Pod Autoscaler using CPU-utilization metrics needs requests as the baseline denominator), and Quality-of-Service classification, making CPU request declaration a basic reliability control, not just a security one.

## How Checkov evaluates this
For raw Kubernetes manifests, `CPURequests` (a `BaseK8sContainerCheck`) inspects each container's `resources` field:
- If `resources` is missing entirely, or is present but not a dict, or `resources.requests` is missing/not a dict, or `requests.cpu` is falsy/absent → **FAIL** (or `UNKNOWN` if `resources`/`requests` exist but aren't the expected dict shape, e.g., unresolved templating).
- **PASS** only if `resources.requests.cpu` is set to a truthy value.

For the Terraform `kubernetes_pod`/`kubernetes_deployment` resources, the equivalent check walks `spec[0]` (drilling into `spec[0].template[0].spec[0]` for Deployments) to find each `container` block, then checks `resources[0].requests[0].cpu`; if any container lacks this, that container **FAILS**, and if no `container` blocks are found at all, the result is `UNKNOWN`.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cvat-redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cvat-redis
  template:
    metadata:
      labels:
        app: cvat-redis
    spec:
      containers:
        - name: redis
          image: redis:7.2
          # no "resources.requests.cpu" set
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cvat-redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cvat-redis
  template:
    metadata:
      labels:
        app: cvat-redis
    spec:
      containers:
        - name: redis
          image: redis:7.2
          resources:
            requests:
              cpu: "100m"    # fix: explicit CPU request
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
```

## Remediation steps
1. Add a `resources.requests.cpu` value to every container spec in Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and bare Pods.
2. Derive the request value from observed real-world usage (e.g., via `kubectl top pod`, VPA recommendations, or historical Prometheus CPU metrics), not a guess — setting it too low defeats the purpose (scheduler under-reserves), and too high wastes cluster capacity.
3. Set a corresponding `resources.limits.cpu` as appropriate for your workload's burst tolerance; note CPU limits (unlike memory) only throttle rather than kill, so limits are a separate design decision from requests.
4. For workloads managed via Kustomize overlays (as flagged in this repo's `kustomization.yaml` examples), add the resource requests either directly in the base Deployment manifest or via a Kustomize patch/overlay so `dev`/`prod` overlays inherit or override appropriately.
5. Re-run Checkov after the fix to confirm the flagged `cvat_redis` and related deployments now pass.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/CPURequests.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/CPURequests.py)
- [Kubernetes docs: Resource requests and limits](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
