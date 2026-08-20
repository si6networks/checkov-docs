# CKV_K8S_29: Apply security context to your pods, deployments and daemon_sets
## Severity
**LOW** (score: 2.0/10)

Omitting a security context leaves a workload with permissive kernel/runtime defaults (e.g. root user, writable filesystem, no dropped capabilities), broadening its attack surface without being an exploit in itself.

## Summary
This check fails Pods/workloads that don't have any `securityContext` defined (at the Pod level in the Kubernetes-native implementation, or per-container in the Terraform implementation), since an absent security context means the workload runs entirely on Kubernetes' permissive defaults rather than an explicitly reviewed hardening baseline.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`, `kubernetes_daemonset`, `kubernetes_daemon_set_v1`

## Why it matters
`securityContext` (at Pod or container level) is where all the meaningful container-hardening controls live: `runAsNonRoot`/`runAsUser`, `privileged`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem`, `capabilities.drop`, seccomp/AppArmor/SELinux profiles, and `fsGroup`. A manifest with no `securityContext` at all is not merely "unhardened" — it is running with every one of these settings at Kubernetes' permissive defaults simultaneously: writable root filesystem, image's default (often root) user, privilege escalation allowed, and the container runtime's default capability set retained (including `NET_RAW`). This check acts as an umbrella signal: its presence (or absence) is a strong proxy for whether a team has done any container-hardening review at all for a given workload, and its absence typically means every other more specific hardening check (CKV_K8S_16/20/22/23/28, etc.) is also failing by default.

## How Checkov evaluates this
- **Kubernetes-native (`PodSecurityContext`):** resolves the effective `spec` (directly for `Pod`, via `spec.jobTemplate.spec.template.spec` for `CronJob`, via `spec.template.spec` otherwise) and checks for the presence of a Pod-level `securityContext` key. If present (any value), PASSED; if absent, FAILED. Note this only checks for existence, not that it contains meaningful hardening settings.
- **Terraform (`PodSecurityContext`):** takes a stricter, per-container approach — it walks `spec[0].container[*]` (or `spec[0].template[0].spec[0].container[*]` for Deployments/DaemonSets) and fails if *any* container is missing its own `security_context` block, regardless of whether a Pod-level one exists.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sim-runner
spec:
  template:
    spec:
      containers:
        - name: sim
          image: myorg/sim:1.0
          # no securityContext anywhere in the pod spec
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sim-runner
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
        - name: sim
          image: myorg/sim:1.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

## Remediation steps
1. Add a Pod-level `securityContext` block (at minimum `runAsNonRoot: true`, `runAsUser`, `fsGroup`) to the affected Deployments under `observability`, `dash`, and `sim` bases/overlays, via a Kustomize patch on their `kustomization.yaml`.
2. Add a container-level `securityContext` to every container as well (`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`), since simply satisfying this check with an empty `securityContext: {}` provides no actual hardening — treat it as the entry point to also fixing CKV_K8S_20/22/23/28.
3. Standardize a hardened `securityContext` template (e.g. via a Kustomize base or Helm chart default) so all new workloads inherit sane defaults rather than each team re-deriving one.
4. Enforce via Pod Security Admission (`baseline`/`restricted`) so future manifests missing key `securityContext` fields are rejected at admission time, not just flagged in CI.
5. Test after applying, since combining this with `runAsNonRoot`/`readOnlyRootFilesystem` may require accompanying image or volume-mount changes (see CKV_K8S_22 and CKV_K8S_23 for details).

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/PodSecurityContext.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/PodSecurityContext.py)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
