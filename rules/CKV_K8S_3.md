# CKV_K8S_3: Do not admit containers wishing to share the host IPC namespace

## Severity
**MEDIUM** (score: 5.0/10)

Allowing `hostIPC: true` via a cluster-wide PodSecurityPolicy lets any admitted pod share the host's IPC namespace, letting a compromised container read or tamper with shared memory used by other workloads or host processes and break container-to-host isolation.

## Summary
This check ensures a Kubernetes `PodSecurityPolicy` does not allow pods to share the host's IPC (inter-process communication) namespace via `hostIPC: true`.

## Applicability
- **Kubernetes manifests**: resource kind `PodSecurityPolicy`, field `spec.hostIPC`.
- **Terraform**: resource type `kubernetes_pod_security_policy`, attribute `spec[0].host_ipc`.

## Why it matters
`hostIPC: true` lets a pod's containers share the host's IPC namespace with all other processes on the node, including other pods and host daemons. IPC objects (System V IPC / POSIX message queues, shared memory segments, semaphores) are visible and accessible to any process attached to the same namespace. A compromised or malicious container with `hostIPC` enabled could read or tamper with shared memory used by other workloads or host processes, potentially leaking secrets held in shared memory or corrupting data used by unrelated applications — effectively breaking the isolation boundary between the container and the host. Because a PodSecurityPolicy is a cluster-wide admission gate, allowing `hostIPC` here means *any* pod validated against this policy is permitted to request that dangerous capability, not just a single workload.

## How Checkov evaluates this
- **Kubernetes check** (`ShareHostIPCPSP`, subclass of `BaseSpecOmittedOrValueCheck`): inspects `spec.hostIPC`. If the key is omitted, or present but not `true`, the check PASSES; if `hostIPC` is explicitly `true`, it FAILS.
- **Terraform check** (`BaseResourceNegativeValueCheck`): inspects `spec[0].host_ipc`. The forbidden value list is `[True]` — if `host_ipc = true` the check FAILS; any other value (including unset) PASSES.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  hostIPC: true
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
```

## Remediated example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  hostIPC: false   # do not allow sharing the host IPC namespace
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
```

## Remediation steps
1. Remove `hostIPC: true` from the `PodSecurityPolicy` spec, or set it explicitly to `false`.
2. In Terraform, remove `host_ipc = true` from the `spec` block of `kubernetes_pod_security_policy`, or set it to `false`.
3. If a specific workload genuinely needs host IPC (rare — e.g. certain HPC or device-plugin workloads), scope a dedicated, narrowly-bound PSP (or, on clusters that have migrated away from PSP, a Pod Security Admission / OPA Gatekeeper policy) to only that workload's service account rather than allowing it broadly.
4. Note that PodSecurityPolicy is deprecated and removed as of Kubernetes 1.25+; on those clusters, enforce the equivalent restriction via Pod Security Admission (`restricted` profile) or an admission controller like Kyverno/OPA Gatekeeper.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ShareHostIPCPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ShareHostIPCPSP.py)
- [Kubernetes docs: Pod Security Policies](https://kubernetes.io/docs/concepts/security/pod-security-policy/)
