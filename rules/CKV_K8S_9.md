# CKV_K8S_9: Readiness Probe Should be Configured
## Severity
**LOW** (score: 2.0/10)

A missing readiness probe is primarily an availability and traffic-routing hygiene issue (pods may receive traffic before they are ready) with no direct confidentiality or integrity impact.

## Summary
This check verifies that every container in a Kubernetes pod-spec (or corresponding Terraform `kubernetes_*` resource) defines a `readinessProbe`, so the platform can determine when the container is actually ready to receive traffic.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

Both Kubernetes YAML manifests and Terraform. Kubernetes entities: `DaemonSet`, `Deployment`, `DeploymentConfig`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet` (explicitly excludes `Job` and `CronJob`, and only evaluates regular `containers`, not `initContainers`). Terraform resources: `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`.

## Why it matters
Without a readiness probe, Kubernetes considers a container "ready" the instant its process starts, even if the application hasn't finished initializing (loading config, warming caches, establishing DB connections, etc.). The kubelet will immediately add the pod's IP to the Service's Endpoints, so live traffic gets routed to a container that isn't actually able to serve requests — causing user-facing errors, failed health checks downstream, and connection timeouts during every deploy or restart. Readiness probes also gate rolling updates: without them, `Deployment` rollouts can mark new pods as available before they're truly serving, defeating the safety guarantees of `maxUnavailable`/`maxSurge` and risking a bad rollout serving 100% of traffic before anyone notices.

## How Checkov evaluates this
**Kubernetes check** (`ReadinessProbe`, a `BaseK8sContainerCheck`): for each container in the pod spec's `containers` list (not `initContainers`), it checks whether `readinessProbe` is set. If `readinessProbe` truthy → PASSED for that container; otherwise FAILED. `Job` and `CronJob` are excluded from `SUPPORTED_ENTITIES` since one-shot/batch workloads generally aren't fronted by a Service and don't need readiness gating.

**Terraform check** (`ReadinessProbe`, a `BaseResourceValueCheck`): inspects the resource's `spec` block. For `kubernetes_deployment`/`kubernetes_deployment_v1` it looks at `spec[0].template[0].spec[0].container[*].readiness_probe`; for `kubernetes_pod`/`kubernetes_pod_v1` it looks at `spec[0].container[*].readiness_probe`. If `containers` key is missing, or any container entry isn't a dict, returns UNKNOWN. Otherwise, PASSED if the (first) container has `readiness_probe` set, FAILED otherwise — note only the first container in the list is actually evaluated due to an early `return` inside the loop.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  selector:
    matchLabels: { app: web }
  template:
    metadata:
      labels: { app: web }
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
          ports:
            - containerPort: 8080
          # no readinessProbe defined
```

```hcl
resource "kubernetes_deployment" "cvat_redis" {
  metadata {
    name = "cvat-redis"
  }
  spec {
    replicas = 1
    selector {
      match_labels = { app = "cvat-redis" }
    }
    template {
      metadata {
        labels = { app = "cvat-redis" }
      }
      spec {
        container {
          name  = "redis"
          image = "redis:7-alpine"
          # no readiness_probe block
        }
      }
    }
  }
}
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  selector:
    matchLabels: { app: web }
  template:
    metadata:
      labels: { app: web }
    spec:
      containers:
        - name: web
          image: myregistry/web:1.4.2
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
```

```hcl
resource "kubernetes_deployment" "cvat_redis" {
  metadata {
    name = "cvat-redis"
  }
  spec {
    replicas = 1
    selector {
      match_labels = { app = "cvat-redis" }
    }
    template {
      metadata {
        labels = { app = "cvat-redis" }
      }
      spec {
        container {
          name  = "redis"
          image = "redis:7-alpine"

          readiness_probe {
            tcp_socket {
              port = 6379
            }
            initial_delay_seconds = 5
            period_seconds         = 10
          }
        }
      }
    }
  }
}
```

## Remediation steps
1. Add a `readinessProbe` (YAML) or `readiness_probe` block (Terraform) to every container in the flagged Deployments/kustomizations, especially `cvat_redis` and the workloads under the `dash`, `cert-manager`, and `argo` kustomizations.
2. Pick the probe type matching the workload: `httpGet` for HTTP services with a health endpoint, `tcpSocket` for plain TCP services (e.g., Redis), or `exec` for a custom readiness command.
3. Tune `initialDelaySeconds`/`periodSeconds`/`failureThreshold` to match realistic startup time — too aggressive a probe can flap a slow-starting container in and out of Service endpoints.
4. Do not add readiness probes to `Job`/`CronJob` pod specs — Checkov intentionally excludes them since batch workloads aren't gated by Service readiness.
5. For third-party Helm charts consumed via `kustomization.yaml`, check if the chart already exposes a `readinessProbe` values field before patching directly; otherwise use a strategic-merge or JSON6902 patch in the kustomization to inject the probe.

## References
- [Checkov Kubernetes check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ReadinessProbe.py)
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ReadinessProbe.py)
- [Kubernetes readiness probe documentation](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#types-of-probe)
