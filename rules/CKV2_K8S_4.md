# CKV2_K8S_4: ServiceAccounts/nodes that can modify services/status may exploit CVE-2020-8554 for MiTM attacks

## Severity
**MEDIUM** (score: 5.0/10)

Write access to services/status enables exploitation of the well-known unpatched CVE-2020-8554 to redirect cluster traffic and perform man-in-the-middle attacks against other workloads.

## Summary
This check ensures no Role/ClusterRole bound to a ServiceAccount or Node grants `update`/`patch` (or `*`) verb permission on the `services/status` subresource, because that permission can be used to exploit CVE-2020-8554 and hijack traffic for arbitrary LoadBalancer-type Services.

## Applicability
Kubernetes manifests. Applies to `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` resource kinds, evaluated as a connected RBAC graph.

## Why it matters
CVE-2020-8554 is an unfixed, by-design Kubernetes design flaw: any identity permitted to create or update Services (specifically to set `status.loadBalancer.ingress.ip`) can point a `ClusterIP`/`ExternalIP`/`LoadBalancer` Service's external endpoint at an IP address it controls. Because Kubernetes networking components (kube-proxy, cloud LB controllers) trust the `status.loadBalancer.ingress.ip` field, an attacker who sets it can intercept traffic intended for that Service — enabling man-in-the-middle attacks against other workloads or even external clients hitting the LoadBalancer IP. The `services/status` subresource specifically controls this status field, so any low-privilege ServiceAccount/Node with `update`/`patch` on it can pull off the attack without needing broader Service edit rights. Since there is no upstream code fix (it's mitigated only via RBAC hygiene and admission control), restricting this permission via RBAC is the primary defense.

## How Checkov evaluates this
Graph-based JSON policy (`ModifyServicesStatus.json`). It:
1. Filters for `ClusterRoleBinding`/`RoleBinding` resources.
2. Passes if the binding has no connected Role/ClusterRole, if no subject is `Node`/`ServiceAccount`, or if the connected Role/ClusterRole rules do NOT intersect `resources: [services/status, *]` or do NOT intersect `verbs: [update, patch, *]`.
3. Fails when a Node/ServiceAccount subject is bound to a Role/ClusterRole granting `update`/`patch`/`*` verb on `services/status` (or `*`) resources.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: svc-status-editor
rules:
- apiGroups: [""]
  resources: ["services/status"]
  verbs: ["update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: svc-status-editor-binding
subjects:
- kind: ServiceAccount
  name: lb-controller-sa
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: svc-status-editor
  apiGroup: rbac.authorization.k8s.io
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: svc-status-editor
rules:
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "watch"]   # 'services/status' update/patch removed
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: svc-status-editor-binding
subjects:
- kind: ServiceAccount
  name: lb-controller-sa
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: svc-status-editor
  apiGroup: rbac.authorization.k8s.io
```

## Remediation steps
1. Find all Roles/ClusterRoles bound to ServiceAccounts/Nodes that grant `update`/`patch` on `services/status`.
2. Remove this permission unless the ServiceAccount belongs to a trusted, audited cloud-controller-manager or LoadBalancer controller component that legitimately needs to write LB status.
3. If the permission is required, restrict the binding to the specific, dedicated controller ServiceAccount only — never grant it broadly (e.g. to `default` service accounts or wildcard subjects).
4. Deploy an admission controller/policy engine (e.g. OPA Gatekeeper, Kyverno) to additionally validate that `status.loadBalancer.ingress.ip` writes only come from the legitimate cloud-provider controller.
5. Track official Kubernetes SIG-Auth guidance on CVE-2020-8554, since there is no code-level patch — mitigation is entirely RBAC/admission-control based.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/graph_checks/ModifyServicesStatus.json
- CVE-2020-8554: https://github.com/kubernetes/kubernetes/issues/97076
