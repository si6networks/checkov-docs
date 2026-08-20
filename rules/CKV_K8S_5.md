# CKV_K8S_5: Containers should not run with allowPrivilegeEscalation
## Severity
**MEDIUM** (score: 5.0/10)

Allowing privilege escalation (via setuid binaries or CAP_SYS_ADMIN) lets a compromised container process gain more privileges than it started with, undermining container isolation and enabling host-level compromise.

## Summary
This check fails a `PodSecurityPolicy` (PSP) if `spec.allowPrivilegeEscalation` is not explicitly set to `false`, since the field defaults to `true` when omitted.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: `PodSecurityPolicy` kind.
- **Terraform**: `kubernetes_pod_security_policy` resource.

Note: PodSecurityPolicy was removed from Kubernetes in v1.25 in favor of Pod Security Admission / Pod Security Standards, so this check is only relevant to clusters on Kubernetes < 1.25 (or those still using a PSP replacement like Gatekeeper/Kyverno policies, which this specific check does not cover).

## Why it matters
`allowPrivilegeEscalation` controls whether a process inside a container can gain more privileges than its parent process (e.g., via a setuid/setgid binary, or `execve` of a binary with file capabilities). This is corresponds to the kernel's `no_new_privs` flag. Per Kubernetes documentation, `allowPrivilegeEscalation` is **always true** if the container runs as privileged or has `CAP_SYS_ADMIN`, but it also independently defaults to `true` for ordinary containers to avoid breaking legacy setuid binaries. If a PSP doesn't force this to `false`, any pod admitted under that policy can run containers where a compromised process (e.g., through a supply-chain-poisoned dependency or an injected exploit) escalates to root or additional capabilities on the node, defeating other container-isolation controls. This maps to CIS Kubernetes Benchmark 1.7.5 (CIS-1.3) / 5.2.5 (CIS-1.5).

## How Checkov evaluates this
Kubernetes check (`AllowPrivilegeEscalationPSP.py`):
- If `spec` is missing → `UNKNOWN`.
- If `spec.allowPrivilegeEscalation` is present and truthy → `FAILED`.
- If `spec.allowPrivilegeEscalation` is present and falsy → `PASSED`.
- If `spec.allowPrivilegeEscalation` is **absent** → `FAILED` (because Kubernetes defaults it to `true`).

Terraform check (`AllowPrivilegeEscalationPSP.py`, a `BaseResourceNegativeValueCheck`): inspects `spec[0].allow_privilege_escalation` and fails if its value is `true`.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  # allowPrivilegeEscalation omitted -> defaults to true -> FAILS
  runAsUser:
    rule: MustRunAsNonRoot
  seLinux:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - configMap
  - secret
```

```hcl
resource "kubernetes_pod_security_policy" "restricted" {
  metadata {
    name = "restricted"
  }
  spec {
    privileged = false
    # allow_privilege_escalation omitted -> defaults true -> FAILS
    run_as_user {
      rule = "MustRunAsNonRoot"
    }
  }
}
```

## Remediated example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false   # explicitly disabled
  runAsUser:
    rule: MustRunAsNonRoot
  seLinux:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - configMap
  - secret
```

```hcl
resource "kubernetes_pod_security_policy" "restricted" {
  metadata {
    name = "restricted"
  }
  spec {
    privileged                 = false
    allow_privilege_escalation  = false  # explicitly disabled
    run_as_user {
      rule = "MustRunAsNonRoot"
    }
  }
}
```

## Remediation steps
1. Add `allowPrivilegeEscalation: false` (or `allow_privilege_escalation = false` in Terraform) explicitly to every `PodSecurityPolicy` spec — never rely on omission.
2. If any specific workload genuinely needs privilege escalation (rare — e.g. certain sidecar proxies), create a dedicated, narrowly-scoped PSP for that workload rather than loosening a shared policy.
3. If your cluster is on Kubernetes 1.25+, PSP is removed; migrate this control to Pod Security Admission (`restricted` profile) or an admission controller like Kyverno/OPA Gatekeeper, and set `securityContext.allowPrivilegeEscalation: false` at the Pod/container level instead.
4. Re-scan with `checkov -d . --check CKV_K8S_5` to confirm PASSED.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/AllowPrivilegeEscalationPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/AllowPrivilegeEscalationPSP.py)
- [Kubernetes Pod Security Policy documentation](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)
- [Kubernetes Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
