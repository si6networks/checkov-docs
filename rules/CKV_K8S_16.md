# CKV_K8S_16: Container should not be privileged
## Severity
**HIGH** (score: 7.5/10)

A privileged container has essentially unrestricted access to the host's devices and kernel, making host compromise from a container breakout trivial.

## Summary
This check fails any Kubernetes container that sets `securityContext.privileged: true`, because privileged containers get essentially unrestricted access to the host — equivalent to root on the node itself.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `PodTemplate`, `Deployment`, `DeploymentConfig`, `ReplicaSet`, `ReplicationController`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
A privileged container is granted (almost) all Linux capabilities and disables most of the kernel-level isolation that containers normally rely on — it can access all devices on the host (`/dev`), bypass cgroup and seccomp restrictions, load kernel modules, and in most configurations mount the host filesystem. This is functionally equivalent to running as root directly on the node. If an attacker compromises the application inside a privileged container (through a code vulnerability, a malicious dependency, or a supply-chain issue), they gain a direct path to full node compromise, and from there frequently the entire cluster (by stealing kubelet credentials, other pods' secrets, or the CNI's host network configuration). This is CIS Kubernetes Benchmark control 1.7.1 / 5.2.1 and is one of the most consequential Pod Security Standards "Restricted"/"Baseline" violations.

## How Checkov evaluates this
- **Kubernetes-native (`PrivilegedContainers`):** for each container, checks `securityContext.privileged`. If it is truthy, the check FAILS. If absent or `false`, it PASSES (Kubernetes itself defaults `privileged` to `false`).
- **Terraform (`PrivilegedContainers`):** walks `spec[0].container[*].security_context[0].privileged` (following `spec.template.spec` for Deployments). Fails if `privileged == [True]`.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: debug-tools
spec:
  containers:
    - name: debug
      image: busybox
      securityContext:
        privileged: true
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: debug-tools
spec:
  containers:
    - name: debug
      image: busybox
      securityContext:
        privileged: false
        capabilities:
          drop: ["ALL"]
```

## Remediation steps
1. Remove `privileged: true` from all container `securityContext` blocks (or set it explicitly to `false`).
2. If the workload needs host-level access for a specific reason (e.g. CNI plugins, storage drivers, monitoring agents), replace blanket privileged mode with the minimal set of Linux `capabilities.add` entries and/or specific `hostPath` volumes actually required.
3. For legitimate infrastructure daemons that truly need privileged mode, isolate them onto dedicated, tightly access-controlled nodes/namespaces and enforce this via a Pod Security Admission "restricted" policy for all other namespaces.
4. Enforce this cluster-wide with Pod Security Standards (`restricted` profile) or an admission controller (Kyverno/OPA Gatekeeper) so future privileged pods are rejected at admission time, not just caught in CI.
5. Audit existing running privileged pods and re-platform them incrementally; expect that removing `privileged` may require adding specific capabilities or securityContext fields to preserve functionality.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/PrivilegedContainers.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/PrivilegedContainer.py)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
