# CKV_K8S_74: Ensure that the --authorization-mode argument is not set to AlwaysAllow
## Severity
**MEDIUM** (score: 5.0/10)

AlwaysAllow authorization mode disables all authorization checks on the API server, letting any authenticated (or even minimally identified) request perform any action, equivalent to a fully open control plane.

## Summary
This check fails a `kube-apiserver` container manifest if its `--authorization-mode` argument includes `AlwaysAllow`, which disables all authorization checks and permits every authenticated (or even unauthenticated) request.

## Applicability
Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
`--authorization-mode` determines which authorization module(s) decide whether a request is permitted after authentication succeeds. `AlwaysAllow` is a no-op authorizer that approves every request unconditionally — it exists mainly for testing/development. If present in a production cluster's `authorization-mode` list, **any** authenticated user or service account (or any anonymous request, if anonymous auth is also enabled — see CKV_K8S_68) can perform any action against the API server: read all secrets, create privileged pods, delete namespaces, modify RBAC itself, etc. This completely voids RBAC and any other access control layered on top, and is one of the most severe possible Kubernetes misconfigurations. This is CIS Kubernetes Benchmark 1.2.6.

## How Checkov evaluates this
`ApiServerAuthorizationModeNotAlwaysAllow.py`: if `command` contains `"kube-apiserver"`, the check scans for a token starting with `--authorization-mode`, splits it on `=` to get the comma-separated modes list, and fails if `"AlwaysAllow"` is one of the modes. If the flag isn't present, or doesn't include `AlwaysAllow`, it passes. Only the first matching `--authorization-mode` token is evaluated (the loop `break`s after processing it).

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
    - --authorization-mode=AlwaysAllow   # disables all access control -> FAILS
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
    - --authorization-mode=Node,RBAC   # real authorization enforced
```

## Remediation steps
1. Remove `AlwaysAllow` from `--authorization-mode` immediately — treat this as a critical/emergency fix if found in any live cluster.
2. Set `--authorization-mode=Node,RBAC` (the standard recommended combination) so requests are authorized via the node authorizer (for kubelets) and RBAC (for everything else).
3. Before rolling out, verify RBAC `ClusterRole`/`ClusterRoleBinding`/`Role`/`RoleBinding` resources exist for every legitimate user/service account that needs access — flipping off `AlwaysAllow` without RBAC in place will break all API access.
4. Test in a staging cluster first: apply the change, then validate representative workloads and CI/CD pipelines still function via `kubectl auth can-i` checks for key identities.
5. Re-scan with `checkov -d . --check CKV_K8S_74`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAuthorizationModeNotAlwaysAllow.py)
- [Kubernetes Authorization documentation](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
