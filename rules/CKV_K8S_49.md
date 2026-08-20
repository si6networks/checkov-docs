# CKV_K8S_49: Minimize wildcard use in Roles and ClusterRoles
## Severity
**MEDIUM** (score: 5.0/10)

Wildcards in Role/ClusterRole rules grant unrestricted API groups, resources, or verbs, letting a compromised or over-scoped identity escalate to near cluster-admin actions across arbitrary resource types.

## Summary
This check fails RBAC `Role`/`ClusterRole` definitions (and their Terraform equivalents) whose first access rule grants permissions using a wildcard (`*`) in `apiGroups`, `resources`, or `verbs`, since wildcards grant far broader access than intended.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: `Role`, `ClusterRole` kinds.
- **Terraform**: `kubernetes_role`, `kubernetes_role_v1`, `kubernetes_cluster_role`, `kubernetes_cluster_role_v1` resources.

## Why it matters
Kubernetes RBAC is the primary authorization boundary inside a cluster. A `Role`/`ClusterRole` rule that uses `*` for `apiGroups`, `resources`, or `verbs` effectively grants unrestricted access to every current and *future* API group/resource/verb the wildcard could match — including ones that don't exist yet at authoring time (e.g., new CRDs, `secrets`, `pods/exec`). This is CIS Kubernetes Benchmark control 5.1.3. A compromised service account or workload bound to such a role becomes a near cluster-admin: it can read secrets, exec into pods, escalate privileges via `bind`/`escalate`/`impersonate` verbs, or modify other workloads. Least-privilege RBAC is one of the most effective blast-radius controls in Kubernetes, and wildcard rules erase it in a single line.

## How Checkov evaluates this
For Kubernetes manifests (`WildcardRoles.py`), the check reads `conf["rules"]` and inspects only the **first** rule entry (`rules[0]`):
- If `apiGroups` contains any string equal to `"*"` → FAIL.
- If `resources` contains any string equal to `"*"` → FAIL.
- If `verbs` contains any string equal to `"*"` → FAIL.
- Otherwise → PASS.

The Terraform version does the same but iterates over **all** `rule` blocks (not just the first), checking `api_groups[0]`, `resources[0]`, and `verbs[0]` for a literal `"*"` character within the first list element.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nuclio-serverless-crd-admin-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

```hcl
resource "kubernetes_role" "nuclio_serverless_crd_admin_role" {
  metadata {
    name      = "nuclio-serverless-crd-admin-role"
    namespace = "nuclio"
  }
  rule {
    api_groups = ["*"]
    resources  = ["*"]
    verbs      = ["*"]
  }
}
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nuclio-serverless-crd-admin-role
rules:
- apiGroups: ["nuclio.io"]
  resources: ["nucliofunctions", "nuclioprojects"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

```hcl
resource "kubernetes_role" "nuclio_serverless_crd_admin_role" {
  metadata {
    name      = "nuclio-serverless-crd-admin-role"
    namespace = "nuclio"
  }
  rule {
    api_groups = ["nuclio.io"]
    resources  = ["nucliofunctions", "nuclioprojects"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }
}
```

## Remediation steps
1. Identify what the workload/service account bound to this role actually needs — use `kubectl auth can-i --list` against the current role as a starting point, or audit API calls with an admission/audit log.
2. Enumerate explicit `apiGroups` (e.g. `""` for core, `apps`, `nuclio.io`), explicit `resources` (e.g. `pods`, `configmaps`, or CRD plural names), and explicit `verbs` (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`) rather than `*`.
3. If multiple resource types need different verb sets, split into multiple `rule` blocks rather than combining them under one wildcard rule.
4. For our flagged resource (`nuclio_serverless_crd_admin_role`), scope `apiGroups`/`resources` to the actual Nuclio CRD group and the specific CRDs/resources the controller manages instead of granting cluster-wide `*`/`*`/`*`.
5. Re-run `checkov -d . --check CKV_K8S_49` to confirm the rule now scans as PASSED.
6. Note: Checkov only inspects the **first** `rules`/`rule` block in the Kubernetes-native check — if you have multiple rule blocks, make sure none of them (not just the first) use wildcards, even though the scanner's Kubernetes check only samples the first entry.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/WildcardRoles.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/WildcardRoles.py)
- [Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
