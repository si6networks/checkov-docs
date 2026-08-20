# CKV_K8S_17: Do not admit containers wishing to share the host process ID namespace
## Severity
**MEDIUM** (score: 5.0/10)

Sharing the host PID namespace lets a container see and interact with (and potentially signal or ptrace) every process on the node, enabling host-level information disclosure and privilege escalation.

## Summary
This check fails any Pod/workload that sets `hostPID: true`, because that setting lets containers in the pod see and interact with every process running on the host node, not just their own.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
Setting `hostPID: true` disables the process-ID namespace isolation that is one of the core container security boundaries. Containers in such a pod can enumerate and inspect every process on the node (via `/proc`), including processes belonging to other pods and the host's own system processes. Combined with sufficient capabilities (e.g. `SYS_PTRACE`) or a writable `/proc/<pid>` entry, this can allow reading another process's memory, environment variables (often containing secrets or credentials), or even injecting into and hijacking another process entirely — a well-known container escape/lateral-movement technique. This maps directly to CIS Kubernetes Benchmark 1.7.2 / 5.2.2 and is disallowed by the Pod Security Standards "Baseline" and "Restricted" profiles.

## How Checkov evaluates this
- **Kubernetes-native (`ShareHostPID`):** locates the effective `spec` (directly for `Pod`; via `spec.jobTemplate.spec.template.spec` for `CronJob`; via `spec.template.spec` for all other controller kinds) and checks the `hostPID` field. If present and truthy, FAILS. Kubernetes defaults this field to `false`, so absence PASSES.
- **Terraform (`ShareHostPID`, a `BaseResourceValueCheck`):** inspects `spec[0].host_pid` (or `spec[0].template[0].spec[0].host_pid` for `kubernetes_deployment`/`kubernetes_deployment_v1`). Expected value is `false`; a missing block is treated as PASSED (Kubernetes default).

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: node-debugger
spec:
  hostPID: true
  containers:
    - name: debugger
      image: busybox
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: node-debugger
spec:
  hostPID: false
  containers:
    - name: debugger
      image: busybox
```

## Remediation steps
1. Remove `hostPID: true` (or set it to `false`) from Pod specs and controller pod templates.
2. If a legitimate node-diagnostic use case requires host process visibility (e.g. a node-level profiler or debugging tool), confine that workload to a dedicated DaemonSet in a tightly restricted, audited namespace rather than allowing it broadly.
3. Enforce this cluster-wide via Pod Security Admission (`baseline` or `restricted` profile) so `hostPID: true` is rejected at admission for all but explicitly exempted namespaces.
4. Combine with least-capability `securityContext` settings — `hostPID` alone is only dangerous when paired with sufficient process-interaction capabilities, so tightening capabilities reduces residual risk if this control is ever bypassed.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ShareHostPID.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ShareHostPID.py)
- [Kubernetes: Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
