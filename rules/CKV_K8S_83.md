# CKV_K8S_83: Ensure that the admission control plugin NamespaceLifecycle is set
## Severity
**LOW** (score: 2.0/10)

Disabling the NamespaceLifecycle admission controller allows objects to be created in terminating or non-existent namespaces, undermining namespace-based isolation and cleanup guarantees rather than directly enabling a privilege escalation path.

## Summary
This check verifies that a self-managed `kube-apiserver` container explicitly enables the `NamespaceLifecycle` admission controller via `--enable-admission-plugins`.

## Applicability
Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant specifically to the container spec of a self-hosted `kube-apiserver` static pod/manifest, not to ordinary application workloads.

## Why it matters
`NamespaceLifecycle` prevents object creation in namespaces that are being terminated or do not exist, and it protects the built-in system namespaces (`default`, `kube-system`, `kube-public`) from deletion. Without this admission controller, a user or misbehaving controller could delete a system namespace, create resources in a namespace that is already terminating (causing an inconsistent cluster state or race conditions), or leave orphaned objects behind after a namespace is removed. This is one of the CIS Kubernetes Benchmark's baseline recommended admission plugins because it closes a class of namespace-lifecycle integrity bugs that could otherwise be exploited to disrupt cluster control-plane state.

## How Checkov evaluates this
The check (`ApiServerNamespaceLifecyclePlugin`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is missing or doesn't include `kube-apiserver`, the container isn't the API server and the check returns PASSED.
2. If `kube-apiserver` is present, Checkov scans each argument:
   - A bare `--enable-admission-plugins` token (no `=value`) → FAILED.
   - `--enable-admission-plugins=<value>` → FAILED unless `NamespaceLifecycle` is a substring of `<value>`.
3. If `--enable-admission-plugins` is never present at all, no FAILED condition is triggered and the check returns PASSED (this is a known limitation — an entirely absent flag is not flagged).

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
      image: registry.k8s.io/kube-apiserver:v1.29.0
      command:
        - kube-apiserver
        - --enable-admission-plugins=NodeRestriction,ServiceAccount,NamespaceLifecycle
        - --etcd-servers=https://127.0.0.1:2379
```

## Remediation steps
1. Find the `kube-apiserver` static pod manifest (typically `/etc/kubernetes/manifests/kube-apiserver.yaml` on kubeadm control-plane nodes).
2. Append `NamespaceLifecycle` to the comma-separated `--enable-admission-plugins` value, without removing existing plugins.
3. On managed Kubernetes offerings (EKS, GKE, AKS), this flag is provider-controlled and typically already includes `NamespaceLifecycle` by default — you will not have a `kube-apiserver` manifest to edit.
4. Save the manifest; the kubelet will detect the change and automatically restart the static pod.
5. Verify the API server started cleanly: `kubectl -n kube-system get pods -l component=kube-apiserver` and check `kubectl -n kube-system logs` for admission-plugin related errors.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerNamespaceLifecyclePlugin.py)
- [Kubernetes admission controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#namespacelifecycle)
