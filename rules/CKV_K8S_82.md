# CKV_K8S_82: Ensure that the admission control plugin ServiceAccount is set
## Severity
**LOW** (score: 2.0/10)

Without the ServiceAccount admission controller enabled, Kubernetes will not enforce ServiceAccount validation and default token mounting controls, weakening a core identity/authorization boundary for workloads.

## Summary
This check verifies that any pod-spec running the `kube-apiserver` binary explicitly enables the `ServiceAccount` admission controller via `--enable-admission-plugins`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice this check is only meaningful for the container spec of a self-managed `kube-apiserver` static pod/manifest (e.g., `/etc/kubernetes/manifests/kube-apiserver.yaml` on a kubeadm control-plane node), not for regular application workloads.

## Why it matters
The `ServiceAccount` admission controller automates the assignment of ServiceAccounts to pods and validates ServiceAccount references and their associated tokens at pod creation time. Without it enabled, ServiceAccount token handling (auto-mounting, validation of the referenced ServiceAccount, and enforcement of imagePullSecrets tied to a ServiceAccount) is not properly enforced by the API server, weakening the identity and authorization model for workloads. Since this is a foundational control-plane admission plugin recommended by the CIS Kubernetes Benchmark, its absence is treated as a control-plane hardening gap that can allow pods to run with unintended or unmanaged default credentials.

## How Checkov evaluates this
The check (`ApiServerServiceAccountPlugin`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is absent, or present but doesn't reference `kube-apiserver`, the check does not apply and defaults to PASSED (the container isn't the API server).
2. If `kube-apiserver` is in the command list, Checkov walks each argument:
   - If it finds a bare `--enable-admission-plugins` token with no `=value` (i.e., value would come from a following separate arg, which this parser doesn't handle) → FAILED.
   - If it finds `--enable-admission-plugins=<value>`, it FAILS unless `ServiceAccount` is a substring of `<value>`.
3. If none of the `--enable-admission-plugins` conditions trigger a FAILED return, the check returns PASSED — note this means if `--enable-admission-plugins` is never set at all, the check still returns PASSED (it only fails when the flag is present but missing `ServiceAccount`).

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
        - --enable-admission-plugins=NodeRestriction,AlwaysPullImages
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
        - --enable-admission-plugins=NodeRestriction,AlwaysPullImages,ServiceAccount
        - --etcd-servers=https://127.0.0.1:2379
```

## Remediation steps
1. Locate the static pod manifest or kubeadm `ClusterConfiguration` that defines `kube-apiserver`'s `--enable-admission-plugins` argument (commonly `/etc/kubernetes/manifests/kube-apiserver.yaml` for kubeadm clusters).
2. Add `ServiceAccount` to the comma-separated list passed to `--enable-admission-plugins`, preserving any existing plugins already enabled.
3. If you manage the control plane via a managed Kubernetes service (EKS, GKE, AKS), this flag is controlled by the provider and is not user-configurable — this check will not be relevant since you won't have a `kube-apiserver` Pod spec in your manifests.
4. After editing a kubeadm static pod manifest, the kubelet automatically restarts the API server container; verify with `kubectl -n kube-system get pods` that it comes back healthy.
5. Confirm the admission plugin is active: `kube-apiserver --enable-admission-plugins` is visible in `ps aux` output on the control-plane node, or check `/etc/kubernetes/manifests/kube-apiserver.yaml`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerServiceAccountPlugin.py)
- [Kubernetes admission controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#serviceaccount)
