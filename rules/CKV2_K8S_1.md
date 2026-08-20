# CKV2_K8S_1: RoleBinding should not allow privilege escalation to a ServiceAccount or Node on other RoleBinding

## Severity
**HIGH** (score: 7.5/10)

Grants a ServiceAccount/Node the ability to create new RoleBindings binding itself to any Role or ClusterRole, enabling privilege escalation to cluster-admin without exploiting any CVE.

## Summary
This check ensures that no `Role`/`ClusterRole` grants `bind` (or wildcard `*`) verb permission on `rolebindings`/`clusterrolebindings` resources to a `ServiceAccount` or `Node` subject, since that permission would let the subject create new RoleBindings that grant itself arbitrary additional privileges.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests. Applies to `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` resource kinds (RBAC objects), evaluated together as a connected graph (a RoleBinding/ClusterRoleBinding linked to the Role/ClusterRole it references).

## Why it matters
Kubernetes RBAC privilege escalation does not require exploiting a CVE — it can be achieved purely through misconfigured permissions. If a ServiceAccount or Node identity is bound (via RoleBinding/ClusterRoleBinding) to a Role/ClusterRole that itself grants `bind` verb on `rolebindings` or `clusterrolebindings` resources, that identity can create brand-new RoleBindings that attach itself (or another principal it controls) to any other Role/ClusterRole in the cluster — including cluster-admin — regardless of whether that identity was otherwise scoped down. This is a classic "second-order" privilege escalation path: a workload compromised through an unrelated vulnerability (e.g. a container escape or SSRF against the Kubernetes API) can use this permission to grant itself cluster-admin and take over the cluster.

## How Checkov evaluates this
This is a graph-based JSON policy (`RoleBindingPE.json`), not a Python check. It:
1. Filters for resources of kind `ClusterRoleBinding` or `RoleBinding`.
2. Passes (does not fail) if any of the following are true:
   - The RoleBinding/ClusterRoleBinding has no connection to a Role/ClusterRole (nothing to evaluate).
   - None of its `subjects[].kind` values are `Node` or `ServiceAccount` (i.e., only Users/Groups are bound — those are external identities Checkov doesn't scope-check this way).
   - It IS connected to a Role/ClusterRole, AND that Role/ClusterRole's `rules` do NOT intersect `resources: [clusterrolebindings, rolebindings, *]` **or** do NOT intersect `verbs: [bind, *]`.
3. Fails only when a RoleBinding/ClusterRoleBinding binds a Node or ServiceAccount subject to a Role/ClusterRole whose rules grant `bind` (or `*`) verb on `rolebindings`/`clusterrolebindings` (or `*`) resources.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: binding-escalator
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["bind", "create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: binding-escalator-binding
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: binding-escalator
  apiGroup: rbac.authorization.k8s.io
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: binding-escalator
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["get", "list"]     # 'bind' removed - can no longer attach itself to new roles
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: binding-escalator-binding
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: binding-escalator
  apiGroup: rbac.authorization.k8s.io
```

## Remediation steps
1. Audit every `Role`/`ClusterRole` bound (via `RoleBinding`/`ClusterRoleBinding`) to a `ServiceAccount` or `Node` subject.
2. Remove the `bind` verb (and any `*` wildcard verb) on `rolebindings`/`clusterrolebindings` resources unless the ServiceAccount is a trusted, cluster-management controller that legitimately needs to manage RBAC bindings (e.g. an operator that provisions namespaces).
3. If a component genuinely needs to create RoleBindings, scope the `bind` permission narrowly using `resourceNames` to specific, non-privileged roles it is allowed to attach — never allow unrestricted `bind` on all rolebindings.
4. Prefer least-privilege ServiceAccounts per workload rather than sharing a broad ClusterRole.
5. Re-run `kubectl auth can-i --as=system:serviceaccount:<ns>:<sa> bind rolebindings` to confirm the fix.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/graph_checks/RoleBindingPE.json
