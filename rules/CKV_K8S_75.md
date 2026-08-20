# CKV_K8S_75: Ensure that the --authorization-mode argument includes Node
## Severity
**MEDIUM** (score: 5.0/10)

Omitting the Node authorizer removes the restriction limiting kubelets to only the API objects relevant to their own node, letting a compromised node read or modify data belonging to other nodes/pods.

## Summary
This check fails a `kube-apiserver` container manifest unless its `--authorization-mode` argument's comma-separated list includes `Node`, the authorization mode that specifically governs kubelet requests to the API server.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
The Node authorizer specifically authorizes API requests made by kubelets, restricting each kubelet to only read objects related to its own node (pods scheduled to it, its own Node object, related endpoints/services, secrets/configmaps referenced by its pods, etc.) via the `system:node` role plus the `system:nodes` group binding. Without `Node` in `--authorization-mode` (e.g., relying solely on RBAC without the node authorizer), a compromised kubelet credential could potentially read or affect objects belonging to other nodes if RBAC bindings are not equally tight, since the node-scoped restriction wouldn't apply. This is CIS Kubernetes Benchmark 1.2.7, and is intended to run in combination with RBAC (`--authorization-mode=Node,RBAC`) as defense-in-depth specifically for the kubelet trust boundary.

## How Checkov evaluates this
`ApiServerAuthorizationModeNode.py`: if `command` contains `"kube-apiserver"`, the check looks for a token starting with `--authorization-mode`, splits the value on `=` then the modes on `,`, and sets `hasNodeAuthorizationMode = True` if `"Node"` appears among them. Returns PASSED only if that flag was found true; FAILED otherwise (including when `--authorization-mode` is entirely absent). If the container doesn't run `kube-apiserver`, passes automatically.

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
    - --authorization-mode=RBAC   # missing Node authorizer -> FAILS
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
    - --authorization-mode=Node,RBAC   # Node authorizer restores per-node scoping
```

## Remediation steps
1. Add `Node` to the `--authorization-mode` comma-separated list, ordering it before `RBAC` (the recommended, commonly documented order is `Node,RBAC`).
2. Verify kubelets are configured to authenticate with certificates that place them in the `system:nodes` group with a `system:node:<nodeName>` common name (standard for kubeadm-bootstrapped kubelets), since the Node authorizer relies on this identity convention.
3. Test that kubelet operations (pod scheduling, status reporting, log/exec, node heartbeats) continue to work after the change — a misconfigured kubelet identity could cause nodes to go `NotReady`.
4. Re-scan with `checkov -d . --check CKV_K8S_75`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAuthorizationModeNode.py)
- [Kubernetes Node Authorization documentation](https://kubernetes.io/docs/reference/access-authn-authz/node/)
