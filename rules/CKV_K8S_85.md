# CKV_K8S_85: Ensure that the admission control plugin NodeRestriction is set
## Severity
**MEDIUM** (score: 5.0/10)

Without NodeRestriction enabled, a compromised kubelet credential can modify or label arbitrary Node and Pod objects beyond its own node, enabling lateral movement and privilege escalation within the cluster.

## Summary
This check verifies that a self-managed `kube-apiserver` container explicitly enables the `NodeRestriction` admission controller via `--enable-admission-plugins`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
`NodeRestriction` limits the `Node` and `Pod` objects a kubelet can modify to only those bound to its own node, and restricts kubelets from modifying labels with the `node-restriction.kubernetes.io/` prefix. Without it, any credential material that leaks from a compromised kubelet/node (which every kubelet inherently has, since kubelets authenticate as members of the `system:nodes` group) could be used to modify or delete other nodes' objects, alter arbitrary pod statuses, or forge labels that scheduler/admission logic depend on for placement and security decisions — effectively allowing lateral movement from one compromised node to control over the entire cluster's node/pod state. This is a standard CIS Kubernetes Benchmark control-plane hardening recommendation.

## How Checkov evaluates this
The check (`ApiServerNodeRestrictionPlugin`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is missing or doesn't include `kube-apiserver`, returns PASSED (not the API server).
2. If `kube-apiserver` is present, scans each argument:
   - Bare `--enable-admission-plugins` (no `=value`) → FAILED.
   - `--enable-admission-plugins=<value>` → FAILED unless `NodeRestriction` is a substring of `<value>`.
3. If `--enable-admission-plugins` is never set, defaults to PASSED (absent flag is not flagged).

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
      image: registry.k8s.io/kube-apiserver:v1.29.0
      command:
        - kube-apiserver
        - --enable-admission-plugins=NamespaceLifecycle,ServiceAccount
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
      image: registry.k8s.io/kube-apiserver:v1.29.0
      command:
        - kube-apiserver
        - --enable-admission-plugins=NamespaceLifecycle,ServiceAccount,NodeRestriction
        - --etcd-servers=https://127.0.0.1:2379
```

## Remediation steps
1. Locate the `kube-apiserver` static pod manifest (e.g., `/etc/kubernetes/manifests/kube-apiserver.yaml` for kubeadm clusters).
2. Add `NodeRestriction` to the comma-separated `--enable-admission-plugins` list.
3. Confirm kubelets are launched with the `system:node:<nodeName>` username format and `system:nodes` group (default for kubeadm and most managed distributions) — `NodeRestriction` depends on this naming convention to scope permissions.
4. Managed Kubernetes providers (EKS, GKE, AKS) enable `NodeRestriction` by default and do not expose a `kube-apiserver` manifest to edit; this check is not actionable there.
5. Save the manifest and let the kubelet restart the static pod automatically; verify with `kubectl -n kube-system get pods` and check for API server errors related to admission plugins.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerNodeRestrictionPlugin.py)
- [Kubernetes admission controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)
