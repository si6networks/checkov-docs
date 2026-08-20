# CKV_K8S_32: Ensure default seccomp profile set to docker/default or runtime/default

## Severity
**LOW** (score: 2.0/10)

A PodSecurityPolicy that fails to mandate a restrictive default seccomp profile permits every pod admitted under it to run with the unconfined syscall filter, widening the kernel attack surface cluster-wide for any compromised container.

## Summary
This check ensures a `PodSecurityPolicy` sets the cluster-wide default seccomp profile annotation to `docker/default` or `runtime/default`, so pods admitted under that policy get a restrictive syscall filter by default.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: resource kind `PodSecurityPolicy`, annotation `seccomp.security.alpha.kubernetes.io/defaultProfileName` on `metadata.annotations`.
- **Terraform**: resource type `kubernetes_pod_security_policy`, same annotation under `metadata[0].annotations`.

## Why it matters
This is the PSP-level counterpart to CKV_K8S_31: instead of relying on every pod author to remember to set a seccomp profile, the PodSecurityPolicy can set a cluster-enforced default so that any pod admitted through it automatically gets syscall filtering, closing the gap for workloads that omit per-pod configuration. Without this default annotation, pods that don't explicitly configure seccomp run unconfined, exposing the full host syscall surface to a compromised container process — a key building block for many container-escape and privilege-escalation exploit chains. Enforcing the default at the policy layer is a defense-in-depth control that removes reliance on every application team getting per-manifest hardening right.

## How Checkov evaluates this
Both the Kubernetes and Terraform checks look at `metadata.annotations["seccomp.security.alpha.kubernetes.io/defaultProfileName"]`. If the annotation is present and its value contains the substring `docker/default` or `runtime/default`, the check PASSES. If the annotation is absent, or set to anything else (e.g. missing entirely, or `unconfined`), the check FAILS.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
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
  annotations:
    seccomp.security.alpha.kubernetes.io/defaultProfileName: runtime/default   # added
spec:
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
1. Add the annotation `seccomp.security.alpha.kubernetes.io/defaultProfileName: runtime/default` (or `docker/default`) to the PSP's `metadata.annotations`.
2. In Terraform, add the same key/value pair to `kubernetes_pod_security_policy.metadata[0].annotations`.
3. Consider also setting `seccomp.security.alpha.kubernetes.io/allowedProfileNames` to restrict which profiles pods are permitted to request, preventing opt-out to `unconfined`.
4. Note this alpha annotation mechanism is tied to PodSecurityPolicy, which is removed in Kubernetes 1.25+. On modern clusters, achieve the same outcome via Pod Security Admission's `restricted`/`baseline` namespace labels, which require `RuntimeDefault` seccomp by default, or via an admission controller (Kyverno/OPA Gatekeeper) that mutates/validates pods to set `seccompProfile.type: RuntimeDefault`.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/SeccompPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/SeccompPSP.py)
- [Kubernetes docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
