# CKV2_K8S_2: Granting `create` permissions to `nodes/proxy` or `pods/exec` sub resources allows potential privilege escalation

## Severity
**HIGH** (score: 7.5/10)

Create access to `pods/exec` or `nodes/proxy` gives a subject the ability to execute arbitrary commands inside any pod or reach the node kubelet API directly, which is effectively remote code execution against workloads and nodes.

## Summary
This check flags RBAC Roles/ClusterRoles bound to a ServiceAccount or Node that grant `create` (or `*`) verb permission on the `nodes/proxy` or `pods/exec` sub-resources, since either permission lets the bound identity execute arbitrary commands inside pods or proxy raw requests to kubelet.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests. Applies to `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` resource kinds, evaluated as a connected RBAC graph.

## Why it matters
`pods/exec` is the subresource behind `kubectl exec` — any identity that can `create` it can open an interactive shell inside any pod matched by the rule, effectively gaining code execution as that pod's runtime user/service account, and from there potentially escaping to the node or accessing mounted secrets/volumes. `nodes/proxy` lets an identity send arbitrary HTTP requests through the kubelet's API on a node (historically including the unauthenticated read-only kubelet port in older clusters), which can expose container logs, allow arbitrary command execution via the kubelet's `exec`/`run` proxy endpoints, or be used to pivot laterally across the cluster. Both are classic, well-documented Kubernetes RBAC privilege-escalation vectors (used, e.g., in CIS Kubernetes Benchmark guidance) because they let a low-trust identity (a compromised app ServiceAccount) reach far beyond its intended scope.

## How Checkov evaluates this
Graph-based JSON policy (`NoCreateNodesProxyOrPodsExec.json`). It:
1. Filters for `ClusterRoleBinding`/`RoleBinding` resources.
2. Passes if the binding has no connected Role/ClusterRole, if none of its `subjects[].kind` are `Node`/`ServiceAccount`, or if the connected Role/ClusterRole's rules do NOT intersect `resources: [pods/exec, nodes/proxy, *]` or do NOT intersect `verbs: [create, *]`.
3. Fails when a Node or ServiceAccount subject is bound to a Role/ClusterRole that grants `create`/`*` verb on `pods/exec` or `nodes/proxy` (or `*`) resources.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: debug-exec-role
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: debug-exec-binding
subjects:
- kind: ServiceAccount
  name: debug-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: debug-exec-role
  apiGroup: rbac.authorization.k8s.io
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: debug-exec-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]   # 'pods/exec' create permission removed
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: debug-exec-binding
subjects:
- kind: ServiceAccount
  name: debug-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: debug-exec-role
  apiGroup: rbac.authorization.k8s.io
```

## Remediation steps
1. Identify all ServiceAccount/Node-bound Roles/ClusterRoles that grant `create` on `pods/exec` or `nodes/proxy`.
2. Remove these permissions from automation/service-account roles; reserve them only for human operator roles that require them for interactive debugging (and pair with audit logging).
3. If exec access is genuinely needed by an operator or CI/CD identity, scope it tightly to a specific namespace and, where the RBAC verb model allows, specific `resourceNames`.
4. Consider using an ephemeral debug container (`kubectl debug`) or ephemeral admin bastion workflow instead of granting standing exec permissions.
5. Enable/verify Kubernetes audit logging on `pods/exec` and `nodes/proxy` calls to detect misuse even after tightening RBAC.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/graph_checks/NoCreateNodesProxyOrPodsExec.json
