# CKV_K8S_68: Ensure that the --anonymous-auth argument is set to false
## Severity
**LOW** (score: 2.0/10)

Anonymous authentication enabled on the API server allows unauthenticated requests to be treated as a system:anonymous user, potentially granting unauthenticated access to the Kubernetes control plane.

## Summary
This check fails a manifest that runs `kube-apiserver` (typically a self-hosted/static-pod control-plane manifest) unless the container's `command` list includes the literal argument `--anonymous-auth=false`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests where a container's `command` invokes `kube-apiserver` — applies broadly to `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet` (i.e., any workload kind that can host a container), because this is a container-level check, not restricted to a specific control-plane kind. In practice it only fires on manifests that actually launch the API server binary (e.g., a kubeadm/self-managed static pod spec for `kube-apiserver`, or a Helm chart that renders one).

## Why it matters
`--anonymous-auth=true` (the historical default) allows requests that fail all other authentication methods to be treated as anonymous, tagged with the `system:anonymous` user and `system:unauthenticated` group. Depending on the cluster's authorization/RBAC configuration, anonymous requests can still hit endpoints that are unintentionally bound to `system:unauthenticated` (a common misconfiguration, and the root cause behind several real-world "unauthenticated cluster takeover" incidents, e.g. exposed unauthenticated `/healthz`, `/metrics`, or worse, misbound RBAC roles). This is CIS Kubernetes Benchmark 1.2.1. Disabling anonymous auth forces every request to be attributable to an authenticated identity, which is a prerequisite for RBAC and audit logging to be meaningful.

## How Checkov evaluates this
`ApiServerAnonymousAuth.py` (a `BaseK8sContainerCheck`) inspects each container's `command` list:
- If `"kube-apiserver"` is one of the command tokens:
  - If `"--anonymous-auth=false"` is **not** present verbatim in `command` → FAILED.
  - Otherwise → PASSED.
- If the container doesn't run `kube-apiserver` at all → PASSED (not applicable).

Note the match is a literal string comparison against `"--anonymous-auth=false"` — any other formatting (e.g., separate `--anonymous-auth` and `false` tokens, or `--anonymous-auth=true`) will not match and will fail.

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
    - --etcd-servers=https://127.0.0.1:2379
    - --authorization-mode=Node,RBAC
    # --anonymous-auth not set -> defaults to true -> FAILS
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
    - --authorization-mode=Node,RBAC
    - --anonymous-auth=false   # explicitly disable anonymous requests
```

## Remediation steps
1. Locate the static pod manifest (usually `/etc/kubernetes/manifests/kube-apiserver.yaml` on control-plane nodes for kubeadm clusters) or the Helm/kustomize template rendering it.
2. Add `--anonymous-auth=false` to the `command` array.
3. If using a managed Kubernetes offering (EKS/GKE/AKS), this flag is controlled by the provider, not user manifests — this check typically only applies to self-managed/on-prem control planes.
4. After changing a static pod manifest, kubelet will automatically restart the API server pod; verify with `kubectl -n kube-system get pod kube-apiserver-<node> -o yaml` that the flag took effect and API access still works for legitimate authenticated clients.
5. Confirm no workflow depends on anonymous access (e.g., unauthenticated health checks hitting the API server directly) before rolling this out cluster-wide.
6. Re-scan with `checkov -d . --check CKV_K8S_68`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAnonymousAuth.py)
- [Kubernetes kube-apiserver reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
