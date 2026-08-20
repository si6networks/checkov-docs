# CKV2_K8S_5: No ServiceAccount/Node should be able to read all secrets

## Severity
**HIGH** (score: 7.5/10)

Unrestricted read access to all Secrets exposes every credential, token, and key stored in the namespace or cluster to a single compromised ServiceAccount or Node, massively expanding breach blast radius.

## Summary
This check ensures no Role/ClusterRole bound to a ServiceAccount or Node grants unrestricted `get`/`watch`/`list` (or `*`) verb permission on `secrets` (or `*`) resources — i.e. without a `resourceNames` restriction limiting it to specific, named secrets.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests. Applies to `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` resource kinds, evaluated as a connected RBAC graph.

## Why it matters
Kubernetes Secrets typically hold TLS private keys, database credentials, API tokens, and other cluster-wide sensitive material. A ServiceAccount or Node granted blanket read access (`get`/`list`/`watch`) to all Secrets in a namespace (or cluster-wide via ClusterRole) can exfiltrate every credential stored there, even ones belonging to completely unrelated workloads. This dramatically expands the blast radius of any single compromised pod: instead of exposing only its own secrets, a breach of one over-privileged ServiceAccount becomes a breach of the whole namespace's (or cluster's) credential store. Node-level unrestricted secret access is especially dangerous because a compromised kubelet/node could read secrets for every pod scheduled on it.

## How Checkov evaluates this
Graph-based JSON policy (`ReadAllSecrets.json`). It:
1. Filters for `ClusterRoleBinding`/`RoleBinding` resources.
2. Passes if the binding has no connected Role/ClusterRole, or if no subject is `Node`/`ServiceAccount`.
3. Also passes (when connected) if the Role/ClusterRole rules do NOT intersect `resources: [secrets, *]`, OR do NOT intersect `verbs: [get, watch, list, *]`, OR the rule DOES have a `resourceNames` field present (meaning access is scoped to specific named secrets rather than "all").
4. Fails when a Node/ServiceAccount subject is bound to a Role/ClusterRole that grants read verbs on `secrets`/`*` with **no** `resourceNames` restriction — i.e., unrestricted read of every secret matched by the rule.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secrets-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]   # no resourceNames -> reads ALL secrets in namespace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secrets-reader-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
roleRef:
  kind: Role
  name: secrets-reader
  apiGroup: rbac.authorization.k8s.io
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secrets-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["app-db-credentials"]   # scoped to only the secret(s) this workload needs
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secrets-reader-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
roleRef:
  kind: Role
  name: secrets-reader
  apiGroup: rbac.authorization.k8s.io
```

## Remediation steps
1. Enumerate all Role/ClusterRole objects bound to ServiceAccounts/Nodes that grant `get`/`list`/`watch` on `secrets` without a `resourceNames` restriction.
2. Add an explicit `resourceNames` list restricting each Role to only the specific secrets that workload requires.
3. If a component genuinely needs to read many/all secrets (e.g. a secrets-management operator like External Secrets Operator or Vault injector), isolate it to its own dedicated, tightly access-controlled namespace and ServiceAccount, and document the exception.
4. Prefer namespaced `Role`/`RoleBinding` over cluster-wide `ClusterRole`/`ClusterRoleBinding` for secret access wherever possible, to limit blast radius.
5. Consider migrating sensitive credentials out of Kubernetes Secrets entirely into an external secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager) with per-workload scoped access, reducing reliance on broad RBAC secret reads.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/graph_checks/ReadAllSecrets.json
