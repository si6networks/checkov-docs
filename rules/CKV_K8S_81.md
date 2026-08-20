# CKV_K8S_81: Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used
## Severity
**LOW** (score: 2.0/10)

Without SecurityContextDeny (when PodSecurityPolicy is absent), the API server has no admission-time control over pod securityContext fields, allowing privileged, host-mounting, or root-forcing pods to be admitted unchecked.

## Summary
This check fails a `kube-apiserver` container manifest if its `--enable-admission-plugins` value contains neither `PodSecurityPolicy` nor `SecurityContextDeny`, meaning no admission-time control is in place to restrict pod `securityContext` settings.

## Applicability
Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
Without `PodSecurityPolicy` (deprecated/removed in 1.25+) or the `SecurityContextDeny` admission plugin active, nothing at admission time stops users/workloads from requesting dangerous `securityContext` settings — privileged containers, host namespace sharing (`hostPID`, `hostIPC`, `hostNetwork`), arbitrary `runAsUser: 0`, added Linux capabilities, or host path mounts. `SecurityContextDeny` is a simple admission controller that denies any pod attempting to set fields in its security context that could escalate privileges relative to the rest of the pod/cluster — it exists specifically as a lightweight substitute for clusters not using PSP. Leaving both controls off means the only backstop against privilege-escalating pod specs is whatever RBAC/other admission webhooks are separately configured (which may not cover this specific dimension), significantly raising the risk that a compromised or careless workload deployment achieves container breakout or host compromise. This is CIS Kubernetes Benchmark 1.2.14 (or similar numbering depending on version).

## How Checkov evaluates this
`ApiServerSecurityContextDenyPlugin.py`: if `command` contains `"kube-apiserver"`, it scans command tokens:
- If a token is exactly `"--enable-admission-plugins"` (no `=value`) → FAILED immediately.
- If a token contains `=`, split into `field`/`value`; if `field == "--enable-admission-plugins"` and **neither** `"PodSecurityPolicy"` **nor** `"SecurityContextDeny"` is a substring of `value` → FAILED.
- Otherwise (either substring is present, or no matching token found at all) → PASSED.

Note: like CKV_K8S_80, this uses substring matching, so it correctly detects either plugin name within a longer comma-separated list.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.24.0
    command:
    - kube-apiserver
    - --etcd-servers=https://127.0.0.1:2379
    - --enable-admission-plugins=NodeRestriction,ResourceQuota
    # neither PodSecurityPolicy nor SecurityContextDeny enabled -> FAILS
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.24.0
    command:
    - kube-apiserver
    - --etcd-servers=https://127.0.0.1:2379
    - --enable-admission-plugins=NodeRestriction,ResourceQuota,SecurityContextDeny
```

## Remediation steps
1. If your cluster still supports PSP (Kubernetes < 1.25) and you already enforce it, ensure `PodSecurityPolicy` is in `--enable-admission-plugins` and appropriate PSPs are bound — that alone satisfies this check.
2. If PSP is not used (either deprecated on your version, or intentionally not adopted), add `SecurityContextDeny` to `--enable-admission-plugins` as a minimal-effort backstop against dangerous `securityContext` fields.
3. For Kubernetes 1.25+ where PSP no longer exists, the durable fix is migrating to Pod Security Admission (`restricted`/`baseline` Pod Security Standards) rather than relying on `SecurityContextDeny`, which is a coarser, all-or-nothing control (it denies most non-default securityContext usage rather than allowing fine-grained policy).
4. Test that legitimate workloads needing specific (safe) securityContext fields (e.g. `runAsNonRoot: true`, `readOnlyRootFilesystem: true`) still deploy successfully — `SecurityContextDeny` can be quite blunt and may reject benign settings; validate in staging.
5. Re-scan with `checkov -d . --check CKV_K8S_81`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerSecurityContextDenyPlugin.py)
- [Kubernetes Admission Controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#securitycontextdeny)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
