# CKV_K8S_157: Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings
## Severity
**MEDIUM** (score: 5.0/10)

Granting the RBAC `bind` verb on RoleBindings/ClusterRoleBindings is a known privilege-escalation primitive that lets a subject attach an arbitrary (potentially cluster-admin) Role to itself or another principal, bypassing RBAC's least-privilege model.

## Summary
This check fails any Kubernetes `Role` or `ClusterRole` that grants the `bind` verb on `rolebindings` or `clusterrolebindings` resources, because that permission lets a subject grant itself (or anyone else) any role it can see — a classic RBAC privilege-escalation primitive.

## Applicability
**Checkov framework(s):** `kubernetes`

- **IaC framework:** Kubernetes manifests (YAML/JSON)
- **Resource/entity types:** `ClusterRole`, `Role`

## Why it matters
Kubernetes RBAC is normally additive and hierarchical — a subject can only grant permissions it already holds when creating a `RoleBinding`/`ClusterRoleBinding`, unless it also holds the `bind` verb on those binding resources. When `bind` is granted, however, Kubernetes' RBAC authorizer allows the holder to bind *any* Role or ClusterRole to *any* subject, including itself, as long as the binding subject also otherwise satisfies escalation checks. In practice this means a low-privileged principal that is merely permitted to `create` RoleBindings/ClusterRoleBindings and also holds `bind` on them can attach a highly privileged ClusterRole (e.g. `cluster-admin`) to its own ServiceAccount, fully escalating to cluster administrator. This is one of the two RBAC verbs (`bind` and `escalate`) explicitly designed as escape hatches from RBAC's "grant no more than you have" rule, so granting them broadly defeats least-privilege RBAC design entirely.

## How Checkov evaluates this
The check (`RbacBindRoleBindings`, subclass of `BaseRbacK8sCheck`) inspects each `Role`/`ClusterRole` manifest's `rules` list. It fails if any rule includes:
- `apiGroups` containing `rbac.authorization.k8s.io`
- `verbs` containing `bind`
- `resources` containing `rolebindings` or `clusterrolebindings`

If no rule matches that combination, the check passes.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pipeline-deployer
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings", "clusterrolebindings"]
    verbs: ["bind", "create", "get", "list"]
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pipeline-deployer
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["get", "list"]  # 'bind' removed — cannot attach arbitrary roles
```

## Remediation steps
1. Search all `Role`/`ClusterRole` manifests for `verbs: [bind, ...]` combined with `resources: [rolebindings, clusterrolebindings]`.
2. Remove the `bind` verb unless the principal genuinely needs to grant existing roles as part of a controlled automation workflow (e.g. a namespace-provisioning controller).
3. If `bind` is required, scope it narrowly with `resourceNames` to specific, pre-approved RoleBindings rather than a blanket grant, and pair it with `resourceNames` restrictions on which Roles can be referenced (via the binding's own scope).
4. Prefer giving automation a small, fixed set of pre-created RoleBindings to manage instead of open-ended bind/create rights.
5. Audit existing bindings of any Role/ClusterRole carrying this permission to confirm it hasn't already been used to escalate privileges.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RbacBindRoleBindings.py)
- [Kubernetes RBAC: privilege escalation prevention and bootstrapping](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping)
