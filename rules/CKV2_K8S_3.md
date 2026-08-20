# CKV2_K8S_3: No ServiceAccount/Node should have `impersonate` permissions for groups/users/service-accounts

## Severity
**HIGH** (score: 7.5/10)

Impersonate permissions let a subject act as any other user, group, or service account it targets, providing a direct, low-effort path to escalate to cluster-admin or any other identity in the cluster.

## Summary
This check ensures no Role/ClusterRole bound to a ServiceAccount or Node grants the `impersonate` (or `*`) verb on `groups`, `users`, or `serviceaccounts` resources, since impersonation lets the bound identity act as any other user, group, or service account in the cluster.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests. Applies to `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` resource kinds, evaluated together as a connected RBAC graph.

## Why it matters
The Kubernetes API server supports impersonation headers (`Impersonate-User`, `Impersonate-Group`, `Impersonate-Extra-*`) that let a caller with the `impersonate` verb on `users`/`groups`/`serviceaccounts` make requests *as if* they were a different identity. If a ServiceAccount or Node has this permission, it can impersonate a highly privileged user (e.g. `system:admin` or any group like `system:masters`) and bypass its own scoped-down RBAC entirely, gaining whatever access the impersonated identity has. This is a direct, unconditional privilege-escalation primitive — it doesn't require exploiting a code vulnerability, just the API permission itself, making it one of the more dangerous RBAC misconfigurations to leave in place on any non-admin workload identity.

## How Checkov evaluates this
Graph-based JSON policy (`ImpersonatePermissions.json`). It:
1. Filters for `ClusterRoleBinding`/`RoleBinding` resources.
2. Passes if the binding has no connected Role/ClusterRole, if no subject is of kind `Node`/`ServiceAccount`, or if the connected Role/ClusterRole rules do NOT intersect `resources: [groups, users, serviceaccounts, *]` or do NOT intersect `verbs: [impersonate, *]`.
3. Fails when a Node/ServiceAccount subject is bound to a Role/ClusterRole granting `impersonate`/`*` verb on `groups`, `users`, `serviceaccounts`, or `*` resources.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: impersonator-binding
subjects:
- kind: ServiceAccount
  name: automation-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: impersonator
  apiGroup: rbac.authorization.k8s.io
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: automation-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]  # impersonate permission removed entirely
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: automation-binding
subjects:
- kind: ServiceAccount
  name: automation-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: automation-role
  apiGroup: rbac.authorization.k8s.io
```

## Remediation steps
1. Search all Role/ClusterRole objects for `impersonate` (or `*`) verbs on `users`, `groups`, or `serviceaccounts` resources.
2. Remove the permission from any Role/ClusterRole bound to a ServiceAccount or Node.
3. If impersonation is truly required (e.g. for a legitimate proxy/aggregated-API-server component), restrict it with `resourceNames` to a small, specific allowlist of identities it may impersonate, and bind it only to a dedicated, tightly access-controlled ServiceAccount — never to a broadly-used one.
4. Confirm no wildcard (`*`) resource or verb rules exist in the same Role that could implicitly grant impersonate.
5. Validate the fix with `kubectl auth can-i impersonate users --as=system:serviceaccount:<ns>:<sa>`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/graph_checks/ImpersonatePermissions.json
