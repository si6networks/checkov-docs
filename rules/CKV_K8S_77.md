# CKV_K8S_77: Ensure that the --authorization-mode argument includes RBAC
## Severity
**LOW** (score: 2.0/10)

Excluding RBAC from the authorization chain removes fine-grained, role-based access control from the API server, risking overly permissive or undifferentiated access to cluster resources.

## Summary
This check fails a `kube-apiserver` container manifest unless its `--authorization-mode` argument's comma-separated list includes `RBAC`, meaning the cluster does not use Role-Based Access Control as an authorization layer.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
RBAC is the standard, fine-grained, declarative authorization mechanism in Kubernetes (`Role`/`ClusterRole` + `RoleBinding`/`ClusterRoleBinding`). If `RBAC` is missing from `--authorization-mode`, the cluster falls back to whatever other authorizer(s) are configured — commonly `AlwaysAllow` (see CKV_K8S_74) or `ABAC` (a static, file-based, much less flexible and rarely-audited authorization scheme). Without RBAC, teams lose the ability to express and audit least-privilege access via native Kubernetes objects, `ServiceAccount` scoping becomes meaningless, and most security tooling/policy frameworks that assume RBAC (e.g., audit of `ClusterRoleBindings`, admission controllers gating on RBAC subjects) stop functioning as intended. This is CIS Kubernetes Benchmark 1.2.7 / 1.2.8 depending on version, and is foundational to nearly every other access-control best practice in a Kubernetes cluster.

## How Checkov evaluates this
`ApiServerAuthorizationModeRBAC.py`: if `command` contains `"kube-apiserver"`, the check looks for a token starting with `--authorization-mode`, splits its value on `=` then on `,`, and sets `hasRBACAuthorizationMode = True` if `"RBAC"` appears among the modes. Returns PASSED only if true; FAILED otherwise (including when the flag is entirely absent). If the container doesn't run `kube-apiserver`, passes automatically.

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
    - --authorization-mode=Node   # RBAC missing -> FAILS
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
    - --authorization-mode=Node,RBAC   # RBAC enforced
```

## Remediation steps
1. Add `RBAC` to the `--authorization-mode` list, typically as `Node,RBAC`.
2. Before enforcing, ensure appropriate `ClusterRole`/`Role` and `ClusterRoleBinding`/`RoleBinding` objects exist to grant access to legitimate users, groups, and service accounts — otherwise enabling RBAC without bindings will lock everyone out.
3. Use the built-in default roles (`cluster-admin`, `admin`, `edit`, `view`) as starting points, then tighten with custom least-privilege roles per CKV_K8S_49 guidance.
4. Test with `kubectl auth can-i --list --as=<user-or-serviceaccount>` for key identities before and after the change.
5. Re-scan with `checkov -d . --check CKV_K8S_77`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAuthorizationModeRBAC.py)
- [Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
