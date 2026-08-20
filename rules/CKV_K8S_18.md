# CKV_K8S_18: Do not admit containers wishing to share the host IPC namespace
## Severity
**MEDIUM** (score: 5.0/10)

Sharing the host IPC namespace exposes shared memory segments and semaphores of host processes to the container, which can be leveraged to read sensitive data or interfere with host processes.

## Summary
This check fails any Pod/workload that sets `hostIPC: true`, because that setting lets containers in the pod read and write the host's shared memory, semaphores, and message queues, breaking inter-process isolation from the node.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
Setting `hostIPC: true` removes the IPC namespace boundary, giving containers access to the host's System V IPC objects and POSIX message queues. Many host processes use shared memory segments to hold sensitive data in memory (application caches, credentials, cryptographic material) or use IPC primitives for control/synchronization. A container with `hostIPC` enabled can enumerate `/proc/*/... ` IPC-related resources, attach to shared memory segments the host or other privileged processes are using, and potentially read or corrupt that data, or exploit IPC-based race conditions to interfere with host-level processes. This is CIS Kubernetes Benchmark 1.7.3 / 5.2.3 and is disallowed under the Pod Security Standards "Baseline"/"Restricted" profiles.

## How Checkov evaluates this
- **Kubernetes-native (`ShareHostIPC`):** resolves the effective `spec` (directly for `Pod`, via `spec.jobTemplate.spec.template.spec` for `CronJob`, via `spec.template.spec` otherwise) and checks `hostIPC`. Truthy value → FAILED. Field defaults to `false`, so absence PASSES.
- **Terraform (`ShareHostIPC`, a `BaseResourceNegativeValueCheck`):** inspects `spec[0].host_ipc` (or `spec[0].template[0].spec[0].host_ipc` for Deployments); the forbidden value is `True`.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shm-worker
spec:
  template:
    spec:
      hostIPC: true
      containers:
        - name: worker
          image: myorg/worker:1.0
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shm-worker
spec:
  template:
    spec:
      hostIPC: false
      containers:
        - name: worker
          image: myorg/worker:1.0
```

## Remediation steps
1. Remove `hostIPC: true` (or set explicitly to `false`) from Pod specs and workload pod templates.
2. If containers within the same Pod need shared memory (e.g. for high-throughput IPC between a sidecar and main container), rely on Pod-scoped IPC namespace sharing (which is the default within a Pod, no `hostIPC` needed) or a shared `emptyDir` volume, rather than sharing the host's IPC namespace.
3. Enforce this cluster-wide with Pod Security Admission (`baseline`/`restricted`) so `hostIPC: true` cannot be admitted outside explicitly exempted, well-audited namespaces.
4. Review any workload currently relying on `hostIPC` (common with legacy database or HPC-style containers) and confirm whether a Pod-scoped alternative removes the need for host sharing before disabling it.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ShareHostIPC.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ShareHostIPC.py)
- [Kubernetes: Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
