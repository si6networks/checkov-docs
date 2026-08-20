# CKV_K8S_158: Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles
## Severity
**MEDIUM** (score: 5.0/10)

Granting the RBAC `escalate` verb lets a subject directly modify Roles/ClusterRoles to grant itself unrestricted permissions, providing an unrestricted path to full cluster-admin takeover.

## Summary
This check fails any Kubernetes `Role` or `ClusterRole` that grants the `escalate` verb on `roles` or `clusterroles` resources, since that permission lets a subject modify a Role/ClusterRole to grant itself permissions it does not currently hold, bypassing RBAC's normal escalation guard.

## Applicability
**Checkov framework(s):** `kubernetes`

- **IaC framework:** Kubernetes manifests (YAML/JSON)
- **Resource/entity types:** `ClusterRole`, `Role`

## Why it matters
By default, Kubernetes' RBAC authorizer prevents a subject from being able to `create` or `update` a Role/ClusterRole that grants permissions the subject itself doesn't already have — this is the "escalation prevention" safeguard. The `escalate` verb is the explicit override for that safeguard: any subject holding `escalate` on `roles`/`clusterroles` can edit those objects to add arbitrary new permissions, including ones it never had, then use the modified role to gain full cluster control. Combined with `update`/`patch` rights on Roles or ClusterRoles, `escalate` effectively grants unbounded privilege escalation — a service account with a seemingly narrow Role can rewrite its own permissions (or any other role) to `cluster-admin`-equivalent access, defeating all namespace and RBAC boundaries.

## How Checkov evaluates this
The check (`RbacEscalateRoles`, subclass of `BaseRbacK8sCheck`) scans each `Role`/`ClusterRole` manifest's `rules` list for any rule with:
- `apiGroups` containing `rbac.authorization.k8s.io`
- `verbs` containing `escalate`
- `resources` containing `roles` or `clusterroles`

If found, the check fails; otherwise it passes.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ci-runner
  namespace: build
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "clusterroles"]
    verbs: ["escalate", "get", "update"]
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ci-runner
  namespace: build
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles"]
    verbs: ["get"]  # 'escalate' removed
```

## Remediation steps
1. Grep all `Role`/`ClusterRole` manifests for `escalate` in `verbs` paired with `roles`/`clusterroles` in `resources`.
2. Remove `escalate` unless there is a deliberate, tightly-controlled administrative automation workflow (e.g. a platform-team operator) that genuinely requires modifying role permissions dynamically.
3. If retained, restrict it via `resourceNames` to a fixed set of Roles, and keep the granting principal's identity tightly access-controlled and audited.
4. Enable and review Kubernetes audit logs for `escalate` usage to detect anomalous privilege changes.
5. Consider using admission controllers (e.g. OPA/Gatekeeper, Kyverno) as a second line of defense against unexpected Role/ClusterRole mutations even if `escalate` is present.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RbacEscalateRoles.py)
- [Kubernetes RBAC: privilege escalation prevention and bootstrapping](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping)
