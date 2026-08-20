# CKV_K8S_6: Do not admit root containers
## Severity
**MEDIUM** (score: 5.0/10)

Permitting root-UID containers (including a MustRunAs range starting at 0) removes a key isolation boundary, making container breakout to root on the host node far more damaging and likely.

## Summary
This check fails a `PodSecurityPolicy` unless `spec.runAsUser.rule` is set to `MustRunAsNonRoot`, or is `MustRunAs` with a UID range whose minimum is strictly greater than 0 (i.e., root, UID 0, is never a permitted user).

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: `PodSecurityPolicy` kind.
- **Terraform**: `kubernetes_pod_security_policy` resource.

Note: PSP is deprecated/removed as of Kubernetes 1.25; on newer clusters this control should be enforced via Pod Security Admission or an admission controller instead.

## Why it matters
Containers running as UID 0 (root) inside the container namespace share the same UID as root on the host if the container escapes its namespace boundary (via a kernel exploit, a misconfigured hostPath mount, a privileged container, or a container-runtime vulnerability). Root-in-container also has more attack surface even without escape: it can write to more of the container filesystem, bypass file-permission checks, and is often required for many container-breakout techniques. This corresponds to CIS Kubernetes Benchmark 1.7.6 (CIS-1.3) / 5.2.6 (CIS-1.5). Requiring `MustRunAsNonRoot`, or a `MustRunAs` UID range starting above 0, ensures that even if the pod spec doesn't request a non-root user, the API server will reject it (or force a UID) rather than silently admitting a root process.

## How Checkov evaluates this
Kubernetes check (`RootContainersPSP.py`) reads `spec.runAsUser`:
- If `rule == "MustRunAsNonRoot"` → PASSED.
- If `rule == "MustRunAs"`: iterate `ranges`; if **any** range has `min == 0` → FAILED; otherwise PASSED.
- Any other case (no `runAsUser`, no `rule`, `rule == "RunAsAny"`, or `MustRunAs` without `ranges`) → FAILED.

Terraform check (`RootContainerPSP.py`) mirrors this on `spec[0].run_as_user[0].rule` and `range[].min`.

## Non-compliant example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: allows-root
spec:
  privileged: false
  runAsUser:
    rule: MustRunAs
    ranges:
    - min: 0        # allows root UID -> FAILS
      max: 65535
```

```hcl
resource "kubernetes_pod_security_policy" "allows_root" {
  metadata {
    name = "allows-root"
  }
  spec {
    privileged = false
    run_as_user {
      rule = "MustRunAs"
      range {
        min = 0     # allows root UID -> FAILS
        max = 65535
      }
    }
  }
}
```

## Remediated example
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: no-root
spec:
  privileged: false
  runAsUser:
    rule: MustRunAsNonRoot   # explicit non-root requirement
```

```hcl
resource "kubernetes_pod_security_policy" "no_root" {
  metadata {
    name = "no-root"
  }
  spec {
    privileged = false
    run_as_user {
      rule = "MustRunAsNonRoot"   # explicit non-root requirement
    }
  }
}
```

## Remediation steps
1. Prefer `runAsUser.rule: MustRunAsNonRoot` — it's the simplest, most conservative option and requires no numeric range management.
2. If your workloads require a fixed, known UID range, use `rule: MustRunAs` with `ranges` whose `min` is `>= 1` (never `0`).
3. Update pod specs bound to this PSP to set `securityContext.runAsUser` to a non-root UID so they aren't rejected once the PSP is tightened.
4. On Kubernetes 1.25+, migrate to Pod Security Admission's `restricted` or `baseline` profile (`runAsNonRoot: true` in the Pod Security Standard) or an OPA Gatekeeper/Kyverno policy enforcing the same constraint.
5. Re-scan with `checkov -d . --check CKV_K8S_6` after the change.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RootContainersPSP.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/RootContainerPSP.py)
- [Kubernetes Pod Security Policy documentation](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
