# CKV_K8S_79: Ensure that the admission control plugin AlwaysAdmit is not set
## Severity
**MEDIUM** (score: 5.0/10)

The AlwaysAdmit admission plugin approves every request without any policy evaluation, nullifying all admission-time security controls and permitting any workload configuration to be deployed unchecked.

## Summary
This check fails a `kube-apiserver` container manifest if its `--enable-admission-plugins` value includes the deprecated `AlwaysAdmit` plugin, which admits every request unconditionally, bypassing all other admission control checks.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
Admission controllers run after authentication/authorization and can mutate or reject requests (e.g., `PodSecurity`, `LimitRanger`, `ResourceQuota`, `NamespaceLifecycle`, `ServiceAccount`). `AlwaysAdmit` is a no-op admission controller that approves everything, effectively disabling all admission-time policy enforcement for whatever isn't covered by other explicitly enabled plugins. It was deprecated in Kubernetes 1.13 and removed in 1.22, precisely because relying on it (or accidentally leaving it enabled) silently disables security/resource-governance controls that operators believe are active — for example, `PodSecurity`/`SecurityContextDeny` enforcement, `ResourceQuota` limits, or `ImagePolicyWebhook` checks can all be bypassed if `AlwaysAdmit` is present and effectively short-circuits the admission chain for uncovered object types. This is CIS Kubernetes Benchmark 1.2.11 (older versions).

## How Checkov evaluates this
`ApiServerAdmissionControlAlwaysAdmit.py`: if `command` contains `"kube-apiserver"`, it scans each command token:
- If a token is exactly `"--enable-admission-plugins"` (flag with no `=value`, i.e. malformed/incomplete) → FAILED immediately.
- If a token contains `=`, split into `field`/`value`; if `field == "--enable-admission-plugins"` and `value == "AlwaysAdmit"` exactly → FAILED.
- Otherwise → PASSED.

Note the equality check on `value` is exact-match against the whole value string, so this only reliably catches `--enable-admission-plugins=AlwaysAdmit` as a sole value, not `AlwaysAdmit` combined with other plugins in a comma list (unlike CKV_K8S_74/75/77 which split on comma).

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
    image: registry.k8s.io/kube-apiserver:v1.20.0
    command:
    - kube-apiserver
    - --etcd-servers=https://127.0.0.1:2379
    - --enable-admission-plugins=AlwaysAdmit   # disables admission control -> FAILS
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
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --etcd-servers=https://127.0.0.1:2379
    - --enable-admission-plugins=NodeRestriction,ResourceQuota   # AlwaysAdmit removed
```

## Remediation steps
1. Remove `AlwaysAdmit` from `--enable-admission-plugins` entirely.
2. Explicitly enumerate the admission plugins you actually want (e.g., `NamespaceLifecycle`, `LimitRanger`, `ServiceAccount`, `NodeRestriction`, `ResourceQuota`, `PodSecurity`, `MutatingAdmissionWebhook`, `ValidatingAdmissionWebhook`) rather than relying on a catch-all.
3. On Kubernetes 1.22+, `AlwaysAdmit` no longer exists as a valid plugin name — the API server will fail to start if referenced, so this is mostly a legacy-cluster concern; upgrading resolves it structurally.
4. After removing it, verify workloads that depend on admission enforcement (quotas, pod security, webhooks) behave as expected — removing `AlwaysAdmit` may cause previously-silently-admitted requests to now be rejected, which is the intended, correct behavior but should be validated in staging first.
5. Re-scan with `checkov -d . --check CKV_K8S_79`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAdmissionControlAlwaysAdmit.py)
- [Kubernetes Admission Controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
