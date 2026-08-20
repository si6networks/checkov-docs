# CKV_K8S_8: Liveness Probe Should be Configured
## Severity
**LOW** (score: 2.0/10)

A missing liveness probe is chiefly an availability/self-healing concern (stuck containers aren't restarted) rather than a direct confidentiality or integrity exposure.

## Summary
This check fails a container definition (in Kubernetes manifests or Terraform `kubernetes_pod`/`kubernetes_deployment` resources) that does not configure a `livenessProbe`, which Kubernetes uses to detect and automatically restart hung or deadlocked containers.

## Applicability
- **Kubernetes manifests**: container-bearing kinds excluding `CronJob`/`Job` — i.e. `DaemonSet`, `Deployment`, `DeploymentConfig`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Only applies to `containers`, not `initContainers` (init containers run to completion and don't need liveness probes).
- **Terraform**: `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1` resources.

## Why it matters
A liveness probe tells the kubelet when to restart a container: if the probe fails repeatedly, Kubernetes kills and restarts the container per its restart policy. Without one, Kubernetes has no way to detect an application that is running (process alive, so the container doesn't crash) but functionally stuck — deadlocked, out of connections in a pool, wedged waiting on a dependency, or otherwise unresponsive. Such containers stay "Running" and keep receiving traffic (if also lacking differentiated readiness handling) or silently stop doing useful work, degrading availability without any automatic remediation and often without alerting until users notice. This is a foundational Kubernetes reliability/self-healing control, not just a "best practice" — its absence directly increases MTTR (mean time to recovery) for a large class of application-level failures since operators must manually detect and restart stuck pods.

## How Checkov evaluates this
Kubernetes check (`LivenessProbe.py`, a `BaseK8sContainerCheck` restricted to `containers` only): passes if the container's `livenessProbe` key is truthy (i.e., present and non-empty); fails otherwise. `CronJob`/`Job` kinds are excluded from `supported_entities` entirely (their pods are expected to run to completion, so a liveness probe is less applicable).

Terraform check (`LivenessProbe.py`, a `BaseResourceValueCheck` with `missing_block_result=FAILED`): walks into `spec[0]` (or, for `kubernetes_deployment`, into `spec[0].template[0].spec[0]`), then each `container` block; fails on the first container missing a `liveness_probe` block. If `container` is entirely absent, result is `UNKNOWN`.

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
        ports:
        - containerPort: 6379
        # no livenessProbe -> FAILS
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
          image = "redis:7.2"
          # no liveness_probe -> FAILS
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
        ports:
        - containerPort: 6379
        livenessProbe:            # added
          tcpSocket:
            port: 6379
          initialDelaySeconds: 10
          periodSeconds: 15
          failureThreshold: 3
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
          image = "redis:7.2"
          liveness_probe {        # added
            tcp_socket {
              port = 6379
            }
            initial_delay_seconds = 10
            period_seconds         = 15
            failure_threshold      = 3
          }
        }
      }
    }
  }
}
```

## Remediation steps
1. Add a `livenessProbe` to every long-running container: use `httpGet` for services with a health endpoint, `tcpSocket` for services that just need port reachability (e.g. Redis), or `exec` for a custom health-check command.
2. Tune `initialDelaySeconds` to be longer than typical startup time (or, on Kubernetes 1.16+, use a `startupProbe` so the liveness probe doesn't fire prematurely during slow starts).
3. Set `failureThreshold`/`periodSeconds` conservatively so transient blips don't trigger unnecessary restarts, but tight enough that a genuinely stuck process is caught in reasonable time.
4. Distinguish liveness from readiness: liveness governs restarts (is the process alive/functional), readiness governs traffic routing (is it ready to serve) — don't conflate them, and add a `readinessProbe` as well where applicable.
5. For our flagged resources (`cvat_redis` and the `observability`, `dash`, `cert-manager` Kustomize bases), add appropriate probes per-container — Redis and similar backing services typically only need a lightweight `tcpSocket` or a protocol-specific ping command.
6. Re-scan with `checkov -d . --check CKV_K8S_8` to confirm.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/LivenessProbe.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/LivenessProbe.py)
- [Kubernetes Liveness/Readiness/Startup Probes documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
