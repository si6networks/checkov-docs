# CKV_K8S_42: Ensure that default service accounts are not actively used (RoleBinding/ClusterRoleBinding)

## Severity
**LOW** (score: 2.0/10)

Binding RBAC permissions to the default ServiceAccount extends real, usable API privileges to every pod in the namespace that hasn't opted out, so a single compromised pod can inherit whatever role was bound, including broad or namespace-wide access.

## Summary
This check ensures no `RoleBinding` or `ClusterRoleBinding` grants RBAC permissions to the `default` ServiceAccount of any namespace.

## Applicability
- **Kubernetes manifests**: resource kinds `RoleBinding`, `ClusterRoleBinding`, field `subjects[]`.
- **Terraform**: resource types `kubernetes_role_binding`, `kubernetes_role_binding_v1`, `kubernetes_cluster_role_binding`, `kubernetes_cluster_role_binding_v1`, attribute `subject[]`.

## Why it matters
This check is the RBAC-side complement to CKV_K8S_41. Even if a namespace's `default` ServiceAccount has automount disabled, explicitly binding a Role or ClusterRole to `subjects: [{kind: ServiceAccount, name: default}]` grants those permissions to *every* pod in the namespace that doesn't specify its own ServiceAccount — an unbounded, implicit population of workloads, including future ones nobody has reviewed yet. Because the `default` account is so easy to bind to accidentally (it's the path of least resistance when someone is debugging RBAC and just wants "something" to work), it commonly accumulates permissions well beyond what any specific workload needs, undermining least privilege and making it hard to reason about "what can talk to the API and with what permissions" during an incident. CIS Benchmark 5.1.5 requires that RBAC permissions be attached only to intentionally-created, individually scoped ServiceAccounts — never to `default`.

## How Checkov evaluates this
The check inspects `subjects[]` (Kubernetes) / `subject[]` (Terraform) on the RoleBinding/ClusterRoleBinding: for each subject entry, if `kind == "ServiceAccount"` and `name == "default"`, the check FAILS immediately. If no subject matches that combination, it PASSES.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-configmap-reader
  namespace: payments
subjects:
  - kind: ServiceAccount
    name: default
    namespace: payments
roleRef:
  kind: Role
  name: configmap-reader
  apiGroup: rbac.authorization.k8s.io
```

## Remediated example
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: configmap-reader-sa
  namespace: payments
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-configmap-reader
  namespace: payments
subjects:
  - kind: ServiceAccount
    name: configmap-reader-sa   # dedicated account instead of default
    namespace: payments
roleRef:
  kind: Role
  name: configmap-reader
  apiGroup: rbac.authorization.k8s.io
```

## Remediation steps
1. Create a dedicated `ServiceAccount` per workload/purpose (e.g. `configmap-reader-sa`) rather than reusing `default`.
2. Update the `subjects` list in the RoleBinding/ClusterRoleBinding to reference the dedicated ServiceAccount instead of `default`.
3. Update the corresponding pod spec's `serviceAccountName` to the new dedicated ServiceAccount so the workload still has the permissions it needs.
4. Also apply CKV_K8S_41 (disable automount on `default`) as defense in depth, in case a future RoleBinding is mistakenly bound to it again.
5. Audit existing bindings cluster-wide (`kubectl get rolebindings,clusterrolebindings -A -o json | jq` filtered for `subjects[].name == "default"`) to find and remediate any that already exist.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DefaultServiceAccountBinding.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/DefaultServiceAccountBinding.py)
- [Kubernetes docs: Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
