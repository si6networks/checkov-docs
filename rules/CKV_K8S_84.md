# CKV_K8S_84: Ensure that the admission control plugin PodSecurityPolicy is set
## Severity
**LOW** (score: 2.0/10)

Without the PodSecurityPolicy (or equivalent) admission controller enforced, pods can be created with privileged settings such as host namespace access or root execution, broadening the container escape and host-compromise attack surface.

## Summary
This check verifies that a self-managed `kube-apiserver` container explicitly enables the (now-deprecated) `PodSecurityPolicy` admission controller via `--enable-admission-plugins`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
`PodSecurityPolicy` (PSP) was the original cluster-wide mechanism for controlling security-sensitive aspects of pod specs — privileged containers, host namespace/network/PID sharing, allowed volume types, required `runAsUser`/`runAsNonRoot`, capabilities, etc. Without an admission controller enforcing pod security constraints, users with permission to create pods can request privileged containers, hostPath mounts, or host networking, any of which can be used to escape container isolation and compromise the underlying node or cluster. Note: PodSecurityPolicy was deprecated in Kubernetes 1.21 and removed entirely in 1.25, replaced by the built-in Pod Security Admission (PSA) controller and the `Pod Security Standards` (baseline/restricted profiles) enforced via namespace labels. For clusters on 1.25+, this specific flag is no longer applicable — the equivalent hardening is enforcing PSA labels on namespaces or using an external policy engine (e.g., Kyverno, OPA/Gatekeeper).

## How Checkov evaluates this
The check (`ApiServerPodSecurityPolicyPlugin`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is missing or doesn't include `kube-apiserver`, the check returns PASSED (not the API server).
2. If `kube-apiserver` is present, Checkov scans each command-line argument:
   - A bare `--enable-admission-plugins` (no `=value`) → FAILED.
   - `--enable-admission-plugins=<value>` → FAILED unless `PodSecurityPolicy` is a substring of `<value>`.
3. If `--enable-admission-plugins` never appears, the check returns PASSED by default (an absent flag isn't flagged as a failure).

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
        - --enable-admission-plugins=NodeRestriction,ServiceAccount
        - --etcd-servers=https://127.0.0.1:2379
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
        - --enable-admission-plugins=NodeRestriction,ServiceAccount,PodSecurityPolicy
        - --etcd-servers=https://127.0.0.1:2379
```

## Remediation steps
1. Determine your Kubernetes control-plane version. If you are on 1.25 or later, `PodSecurityPolicy` no longer exists as an API object or admission plugin — skip this check and instead adopt Pod Security Admission by labeling namespaces (`pod-security.kubernetes.io/enforce: restricted`) or an external admission controller like Kyverno/OPA Gatekeeper.
2. If on 1.21–1.24 (deprecated but still available), locate the `kube-apiserver` static pod manifest and add `PodSecurityPolicy` to the `--enable-admission-plugins` list.
3. Before enabling PSP enforcement, ensure you have defined and bound at least one permissive `PodSecurityPolicy` object with matching `ClusterRoleBinding`s — enabling the plugin with zero policies defined blocks ALL pod creation cluster-wide.
4. Test in a staging cluster first; enabling PSP without proper policy coverage is a common cause of cluster-wide outages.
5. Plan a migration to Pod Security Admission ahead of any upgrade to Kubernetes 1.25+, since PSP removal is not backward compatible.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerPodSecurityPolicyPlugin.py)
- [Kubernetes Pod Security Standards (PSP replacement)](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
